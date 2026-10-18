#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

namespace sova::pir
{
    inline constexpr size_t pbc_invalid_index = std::numeric_limits<size_t>::max();

    struct PBCParams
    {
        size_t num_entries = 0;
        size_t batch_size = 0;
        size_t num_hash_funcs = 3;
        double cuckoo_factor = 1.2;
        size_t max_attempts = 500;
        uint64_t padding_value = 0;
    };

    struct BucketPlacement
    {
        size_t bucket_index = 0;
        size_t slot_index = 0;

        bool operator==(const BucketPlacement &other) const = default;
    };

    struct PBCPublicParams
    {
        PBCParams params;
        size_t num_buckets = 0;
        size_t max_bucket_size = 0;
        std::vector<std::vector<size_t>> candidate_buckets;
        std::vector<std::vector<BucketPlacement>> index_placements;
    };

    struct PBCServerState
    {
        // The bucket payloads are deliberately not stored: the SOVA construction only needs
        // the bucket sizes and the global indices (in insertion order) of every bucket.
        std::vector<size_t> actual_bucket_sizes;
        std::vector<std::vector<size_t>> bucket_global_indices;
    };

    struct PBCQueryAssignment
    {
        size_t query_position = 0;
        size_t global_index = 0;
        BucketPlacement placement;
    };

    struct PBCQueryPlan
    {
        std::vector<size_t> bucket_to_query_position;
        std::vector<PBCQueryAssignment> assignments;
    };

    void BuildPBCBuckets(
        const std::vector<uint64_t> &database,
        const PBCParams &params,
        PBCPublicParams &public_params,
        PBCServerState &server_state);

    BucketPlacement FindBucketPlacement(
        const PBCPublicParams &public_params,
        size_t global_index,
        size_t bucket_index);

    void AssignBatchIndicesToBucketsMatching(
        const PBCPublicParams &public_params,
        const std::vector<size_t> &batch_indices,
        PBCQueryPlan &query_plan);

    void AssignBatchIndicesToBucketsCuckoo(
        const PBCPublicParams &public_params,
        const std::vector<size_t> &batch_indices,
        PBCQueryPlan &query_plan);

    void AssignBatchIndicesToBuckets(
        const PBCPublicParams &public_params,
        const std::vector<size_t> &batch_indices,
        PBCQueryPlan &query_plan);
}
