#include "pbc.h"

#include <algorithm>
#include <cmath>
#include <functional>
#include <random>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <utility>

namespace sova::pir
{
    namespace
    {
        void validate_pbc_params(const PBCParams &params)
        {
            if (params.num_entries == 0)
            {
                throw std::invalid_argument("PBC num_entries must be positive");
            }
            if (params.batch_size == 0)
            {
                throw std::invalid_argument("PBC batch_size must be positive");
            }
            if (params.num_hash_funcs == 0)
            {
                throw std::invalid_argument("PBC num_hash_funcs must be positive");
            }
            if (params.cuckoo_factor < 1.0)
            {
                throw std::invalid_argument("PBC cuckoo_factor must be at least 1.0");
            }
            if (params.max_attempts == 0)
            {
                throw std::invalid_argument("PBC max_attempts must be positive");
            }
        }

        size_t compute_num_buckets(const PBCParams &params)
        {
            return static_cast<size_t>(std::ceil(params.cuckoo_factor * static_cast<double>(params.batch_size)));
        }

        size_t hash_bucket(size_t hash_id, size_t nonce, size_t global_index, size_t num_buckets)
        {
            std::hash<std::string> hasher;
            std::string material = std::to_string(hash_id) + "|" +
                                   std::to_string(nonce) + "|" +
                                   std::to_string(global_index);
            return hasher(material) % num_buckets;
        }

        std::vector<size_t> candidate_buckets_for_index(
            size_t global_index,
            size_t num_hash_funcs,
            size_t num_buckets)
        {
            std::vector<size_t> candidates;
            candidates.reserve(num_hash_funcs);

            for (size_t hash_id = 0; hash_id < num_hash_funcs; hash_id++)
            {
                size_t nonce = 0;
                size_t bucket = hash_bucket(hash_id, nonce, global_index, num_buckets);
                while (std::find(candidates.begin(), candidates.end(), bucket) != candidates.end())
                {
                    nonce++;
                    bucket = hash_bucket(hash_id, nonce, global_index, num_buckets);
                }
                candidates.push_back(bucket);
            }

            return candidates;
        }

        void validate_public_params(const PBCPublicParams &public_params)
        {
            validate_pbc_params(public_params.params);
            if (public_params.num_buckets == 0)
            {
                throw std::invalid_argument("PBC public params are not initialized");
            }
            if (public_params.candidate_buckets.size() != public_params.params.num_entries)
            {
                throw std::invalid_argument("PBC candidate bucket table has invalid size");
            }
            if (public_params.index_placements.size() != public_params.params.num_entries)
            {
                throw std::invalid_argument("PBC placement table has invalid size");
            }
        }

        void validate_batch_indices(
            const PBCPublicParams &public_params,
            const std::vector<size_t> &batch_indices)
        {
            if (batch_indices.size() != public_params.params.batch_size)
            {
                throw std::invalid_argument("batch size must match PBC params");
            }

            std::unordered_set<size_t> unique_indices;
            for (size_t global_index : batch_indices)
            {
                if (global_index >= public_params.params.num_entries)
                {
                    throw std::invalid_argument("batch index out of range");
                }
                if (!unique_indices.insert(global_index).second)
                {
                    throw std::invalid_argument("duplicate batch indices are not supported");
                }
            }
        }

        std::vector<std::vector<size_t>> build_query_candidates(
            const PBCPublicParams &public_params,
            const std::vector<size_t> &batch_indices)
        {
            std::vector<std::vector<size_t>> query_candidates(batch_indices.size());
            for (size_t query_position = 0; query_position < batch_indices.size(); query_position++)
            {
                query_candidates[query_position] = public_params.candidate_buckets[batch_indices[query_position]];
            }
            return query_candidates;
        }

        void build_query_plan_from_query_to_bucket(
            const PBCPublicParams &public_params,
            const std::vector<size_t> &batch_indices,
            const std::vector<size_t> &query_to_bucket,
            PBCQueryPlan &query_plan)
        {
            if (query_to_bucket.size() != batch_indices.size())
            {
                throw std::invalid_argument("query_to_bucket size mismatch");
            }

            query_plan = {};
            query_plan.bucket_to_query_position.assign(public_params.num_buckets, pbc_invalid_index);
            query_plan.assignments.resize(batch_indices.size());

            for (size_t query_position = 0; query_position < batch_indices.size(); query_position++)
            {
                size_t bucket_index = query_to_bucket[query_position];
                if (bucket_index == pbc_invalid_index)
                {
                    throw std::runtime_error("internal error: query was not assigned to any bucket");
                }
                if (bucket_index >= public_params.num_buckets)
                {
                    throw std::runtime_error("internal error: assigned bucket is out of range");
                }
                if (query_plan.bucket_to_query_position[bucket_index] != pbc_invalid_index)
                {
                    throw std::runtime_error("internal error: multiple queries assigned to the same bucket");
                }

                query_plan.bucket_to_query_position[bucket_index] = query_position;
                query_plan.assignments[query_position] = {
                    query_position,
                    batch_indices[query_position],
                    FindBucketPlacement(public_params, batch_indices[query_position], bucket_index)};
            }
        }

        uint64_t deterministic_batch_seed(const std::vector<size_t> &batch_indices)
        {
            uint64_t seed = 1469598103934665603ULL;
            for (size_t value : batch_indices)
            {
                seed ^= static_cast<uint64_t>(value) + 0x9e3779b97f4a7c15ULL;
                seed *= 1099511628211ULL;
            }
            return seed;
        }
    }

    void BuildPBCBuckets(
        const std::vector<uint64_t> &database,
        const PBCParams &params,
        PBCPublicParams &public_params,
        PBCServerState &server_state)
    {
        validate_pbc_params(params);
        if (database.size() != params.num_entries)
        {
            throw std::invalid_argument("database size must match PBC num_entries");
        }

        public_params = {};
        public_params.params = params;
        public_params.num_buckets = compute_num_buckets(params);
        if (public_params.num_buckets == 0)
        {
            throw std::invalid_argument("PBC number of buckets must be positive");
        }
        if (public_params.num_buckets < params.num_hash_funcs)
        {
            throw std::invalid_argument("PBC number of buckets must be at least num_hash_funcs");
        }

        server_state = {};
        server_state.actual_bucket_sizes.assign(public_params.num_buckets, 0);
        server_state.bucket_global_indices.assign(public_params.num_buckets, {});
        public_params.candidate_buckets.resize(params.num_entries);
        public_params.index_placements.resize(params.num_entries);

        // First pass: candidate buckets and the resulting per-bucket item counts. The counts
        // allow every bucket to be reserved exactly once instead of growing repeatedly.
        for (size_t global_index = 0; global_index < params.num_entries; global_index++)
        {
            auto candidates = candidate_buckets_for_index(
                global_index,
                params.num_hash_funcs,
                public_params.num_buckets);
            public_params.index_placements[global_index].reserve(candidates.size());
            for (size_t bucket_index : candidates)
            {
                server_state.actual_bucket_sizes[bucket_index] += 1;
            }
            public_params.candidate_buckets[global_index] = std::move(candidates);
        }

        for (size_t bucket_index = 0; bucket_index < public_params.num_buckets; bucket_index++)
        {
            const size_t bucket_size = server_state.actual_bucket_sizes[bucket_index];
            server_state.bucket_global_indices[bucket_index].reserve(bucket_size);
            public_params.max_bucket_size = std::max(public_params.max_bucket_size, bucket_size);
        }

        // Second pass: fill the bucket index lists. The traversal order is unchanged, so the
        // slot indices stored in index_placements still match bucket_global_indices.
        for (size_t global_index = 0; global_index < params.num_entries; global_index++)
        {
            for (size_t bucket_index : public_params.candidate_buckets[global_index])
            {
                const size_t slot_index =
                    server_state.bucket_global_indices[bucket_index].size();
                server_state.bucket_global_indices[bucket_index].push_back(global_index);
                public_params.index_placements[global_index].push_back({bucket_index, slot_index});
            }
        }
    }

    BucketPlacement FindBucketPlacement(
        const PBCPublicParams &public_params,
        size_t global_index,
        size_t bucket_index)
    {
        validate_public_params(public_params);
        if (global_index >= public_params.params.num_entries)
        {
            throw std::invalid_argument("global index out of range");
        }

        for (const auto &placement : public_params.index_placements[global_index])
        {
            if (placement.bucket_index == bucket_index)
            {
                return placement;
            }
        }

        throw std::invalid_argument("bucket is not a candidate for the requested global index");
    }

    void AssignBatchIndicesToBucketsMatching(
        const PBCPublicParams &public_params,
        const std::vector<size_t> &batch_indices,
        PBCQueryPlan &query_plan)
    {
        validate_public_params(public_params);
        validate_batch_indices(public_params, batch_indices);

        std::vector<std::vector<size_t>> query_candidates = build_query_candidates(public_params, batch_indices);

        std::vector<size_t> bucket_to_query_position(public_params.num_buckets, pbc_invalid_index);
        std::vector<size_t> query_to_bucket(batch_indices.size(), pbc_invalid_index);

        std::function<bool(size_t, std::vector<uint8_t> &)> try_assign =
            [&](size_t query_position, std::vector<uint8_t> &visited_buckets) -> bool
        {
            for (size_t bucket_index : query_candidates[query_position])
            {
                if (visited_buckets[bucket_index] != 0)
                {
                    continue;
                }
                visited_buckets[bucket_index] = 1;

                if (bucket_to_query_position[bucket_index] == pbc_invalid_index)
                {
                    bucket_to_query_position[bucket_index] = query_position;
                    query_to_bucket[query_position] = bucket_index;
                    return true;
                }

                size_t displaced_query_position = bucket_to_query_position[bucket_index];
                if (displaced_query_position == query_position)
                {
                    continue;
                }

                if (try_assign(displaced_query_position, visited_buckets))
                {
                    bucket_to_query_position[bucket_index] = query_position;
                    query_to_bucket[query_position] = bucket_index;
                    return true;
                }
            }

            return false;
        };

        for (size_t query_position = 0; query_position < batch_indices.size(); query_position++)
        {
            std::vector<uint8_t> visited_buckets(public_params.num_buckets, 0);
            if (!try_assign(query_position, visited_buckets))
            {
                throw std::runtime_error("failed to assign batch indices to distinct buckets");
            }
        }

        build_query_plan_from_query_to_bucket(
            public_params,
            batch_indices,
            query_to_bucket,
            query_plan);
    }

    void AssignBatchIndicesToBucketsCuckoo(
        const PBCPublicParams &public_params,
        const std::vector<size_t> &batch_indices,
        PBCQueryPlan &query_plan)
    {
        validate_public_params(public_params);
        validate_batch_indices(public_params, batch_indices);

        std::vector<std::vector<size_t>> query_candidates = build_query_candidates(public_params, batch_indices);
        uint64_t base_seed = deterministic_batch_seed(batch_indices);

        for (size_t restart = 0; restart < public_params.params.max_attempts; restart++)
        {
            std::vector<size_t> bucket_to_query_position(public_params.num_buckets, pbc_invalid_index);
            std::vector<size_t> query_to_bucket(batch_indices.size(), pbc_invalid_index);
            std::mt19937_64 generator(base_seed + restart);

            std::function<bool(size_t, size_t)> cuckoo_insert =
                [&](size_t query_position, size_t depth) -> bool
            {
                if (depth >= public_params.params.max_attempts)
                {
                    return false;
                }

                const auto &candidates = query_candidates[query_position];
                for (size_t bucket_index : candidates)
                {
                    if (bucket_to_query_position[bucket_index] == pbc_invalid_index)
                    {
                        bucket_to_query_position[bucket_index] = query_position;
                        query_to_bucket[query_position] = bucket_index;
                        return true;
                    }
                }

                std::uniform_int_distribution<size_t> distribution(0, candidates.size() - 1);
                size_t picked_bucket = candidates[distribution(generator)];
                size_t displaced_query = bucket_to_query_position[picked_bucket];

                bucket_to_query_position[picked_bucket] = query_position;
                query_to_bucket[query_position] = picked_bucket;
                query_to_bucket[displaced_query] = pbc_invalid_index;

                if (cuckoo_insert(displaced_query, depth + 1))
                {
                    return true;
                }

                bucket_to_query_position[picked_bucket] = displaced_query;
                query_to_bucket[displaced_query] = picked_bucket;
                query_to_bucket[query_position] = pbc_invalid_index;
                return false;
            };

            bool success = true;
            for (size_t query_position = 0; query_position < batch_indices.size(); query_position++)
            {
                if (!cuckoo_insert(query_position, 0))
                {
                    success = false;
                    break;
                }
            }

            if (success)
            {
                build_query_plan_from_query_to_bucket(
                    public_params,
                    batch_indices,
                    query_to_bucket,
                    query_plan);
                return;
            }
        }

        throw std::runtime_error("failed to assign batch indices with cuckoo insertion");
    }

    void AssignBatchIndicesToBuckets(
        const PBCPublicParams &public_params,
        const std::vector<size_t> &batch_indices,
        PBCQueryPlan &query_plan)
    {
        AssignBatchIndicesToBucketsMatching(public_params, batch_indices, query_plan);
    }
}
