#include "sova_batch_protocol.h"
#include "seal/randomgen.h"
#include "matmul.h"
#include "public_matrix.h"
#include "seal/util/ntt.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/uintarithsmallmod.h"
#include <iomanip>
#include <algorithm>
#include <bit>
#include <chrono>
#include <cmath>
#include <cstring>
#include <limits>
#include <numeric>
#include <random>
#include <sstream>
#include <stdexcept>

namespace sova::pir
{
    using namespace seal;

    namespace
    {
        constexpr uint64_t lwe_modulus = (1ULL << 32);
        constexpr uint64_t sova_plain_modulus = 65537;
        constexpr size_t min_secure_lwe_dimension = 1024;
        constexpr uint64_t crs_domain_evaluation = 1;
        constexpr uint64_t crs_domain_selector = 2;
        constexpr uint64_t crs_domain_galois = 3;
        constexpr uint64_t crs_domain_relinearization = 4;

        // Number of RNS limbs that carry data in the accumulated pages. The response is
        // modulus-switched to the next (smaller) context before it is returned, so the
        // highest limb is never needed and stays zero all the way through. Keeping this
        // explicit lets the inverse NTT skip the structurally zero limbs.
        constexpr size_t accumulated_limbs = 2;

        uint64_t splitmix64(uint64_t &state)
        {
            uint64_t value = (state += 0x9e3779b97f4a7c15ULL);
            value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
            value = (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
            return value ^ (value >> 31);
        }

        prng_seed_type derive_crs_seed(uint64_t master, uint64_t domain, uint64_t index)
        {
	    seal::SOVASeedTimer seed_timer;
            uint64_t state = master ^ (domain * 0xd6e8feb86659fd93ULL) ^
                (index * 0xa0761d6478bd642fULL);
            prng_seed_type seed{};
            auto *seed_bytes = reinterpret_cast<seal_byte *>(seed.data());
            for (size_t offset = 0; offset < prng_seed_byte_count; offset += sizeof(uint64_t))
            {
                uint64_t word = splitmix64(state);
                std::memcpy(seed_bytes + offset, &word,
                    std::min(sizeof(uint64_t), prng_seed_byte_count - offset));
            }
            return seed;
        }

        std::vector<uint32_t> sova_galois_elts(const SEALContext &context, size_t lwe_dimension)
        {
            std::vector<uint32_t> result;
            auto tool = context.key_context_data()->galois_tool();
            for (size_t step = 1; step < lwe_dimension; step <<= 1)
            {
                result.push_back(tool->get_elt_from_step(static_cast<int>(step)));
            }
            return result;
        }

        std::vector<prng_seed_type> sova_key_seeds(
            uint64_t master, uint64_t domain, size_t count)
        {
            std::vector<prng_seed_type> result(count);
            for (size_t i = 0; i < count; i++)
            {
                result[i] = derive_crs_seed(master, domain, i);
            }
            return result;
        }

        size_t ceil_div(size_t x, size_t y)
        {
            return (x + y - 1) / y;
        }

        size_t round_up_to_multiple(size_t value, size_t multiple)
        {
            const size_t remainder = value % multiple;
            return remainder ? value + multiple - remainder : value;
        }

        void build_bucket_partitions(
            size_t bucket_count, size_t slot_count, size_t record_size,
            std::vector<SOVABucketPartition> &partitions, size_t &total_pages)
        {
            partitions.clear();
            total_pages = 0;
            size_t begin = 0;
            size_t remaining = bucket_count;
            while (remaining)
            {
                const size_t group_size = std::bit_floor(remaining);
                SOVABucketPartition partition;
                partition.bucket_begin = begin;
                partition.bucket_count = group_size;
                partition.slots_per_bucket = slot_count / group_size;
                partition.num_pages = ceil_div(record_size, partition.slots_per_bucket);
                partition.response_page_offset = total_pages;
                partitions.push_back(partition);
                begin += group_size;
                remaining -= group_size;
                total_pages += partition.num_pages;
            }
        }

        void pack_database_u8(
            const std::vector<uint64_t> &database, size_t rows, size_t cols,
            PackedDatabase &packed)
        {
            constexpr size_t row_block = 8;
            constexpr size_t compression = 4;
            packed = {};
            packed.rows = rows;
            packed.cols = cols;
            packed.padded_rows = round_up_to_multiple(rows, row_block);
            packed.padded_cols = round_up_to_multiple(cols, compression);
            packed.packed_cols = packed.padded_cols / compression;
            packed.data.assign(packed.padded_rows * packed.packed_cols, 0);
            for (size_t row = 0; row < rows; row++)
            {
                for (size_t col = 0; col < cols; col++)
                {
                    packed.data[row * packed.packed_cols + col / compression] |=
                        static_cast<uint32_t>(database[row * cols + col]) << ((col % compression) * 8);
                }
            }
        }

        void simplepir_setup(
            const std::vector<uint64_t> &database,
            const SOVASimplePIRParams &params,
            SOVASimplePIRPublicParams &public_params,
            SOVASimplePIRServerState &server_state)
        {
            public_params.params = params;
            pack_database_u8(database, params.rows, params.cols, server_state.packed_database);
            // The unpacked 64-bit copy is only a fallback for layouts that cannot be byte
            // packed (empty packed database). Keeping it unconditionally duplicated the whole
            // server database at eight bytes per matrix entry for nothing.
            if (server_state.packed_database.empty())
            {
                server_state.database = database;
            }
            else
            {
                server_state.database.clear();
                server_state.database.shrink_to_fit();
            }
            sample_public_matrix_seed(public_params.public_matrix_seed);
            if (params.benchmark_randomize_hint_matrix)
            {
                sample_random_hint_matrix(params.rows, params.lwe_dimension, server_state.hint_matrix);
            }
            else
            {
                compute_hint_matrix_from_seed(
                    database, params.rows, params.cols, public_params.public_matrix_seed,
                    params.lwe_dimension, server_state.hint_matrix);
            }
        }

        void validate_batch_params(const SOVAParams &params)
        {
            if (params.lwe_dimension == 0)
            {
                throw std::invalid_argument("lwe_dimension must be positive");
            }
            if (params.lwe_dimension < min_secure_lwe_dimension)
            {
                throw std::invalid_argument("lwe_dimension must be at least 1024 for the current security target");
            }
            if (params.record_plain_modulus == 0)
            {
                throw std::invalid_argument("record_plain_modulus must be positive");
            }
            if (params.record_size_bytes == 0)
            {
                throw std::invalid_argument("record_size_bytes must be positive");
            }
            if (params.record_plain_modulus > 256)
            {
                throw std::invalid_argument("record_plain_modulus must be at most 256 for byte-packed records");
            }
            if (params.pbc_params.padding_value >= params.record_plain_modulus)
            {
                throw std::invalid_argument("padding_value must be smaller than record_plain_modulus");
            }
            if (params.pbc_params.batch_size <= 1 ||
                !std::has_single_bit(params.pbc_params.batch_size))
            {
                throw std::invalid_argument("batch_size must be 2^k with integer k > 0");
            }
            if (!std::has_single_bit(params.pbc_params.num_entries))
            {
                throw std::invalid_argument("num_entries must be a power of two");
            }
            if (!std::has_single_bit(params.record_size_bytes))
            {
                throw std::invalid_argument("record_size_bytes must be a power of two");
            }
        }

        void validate_batch_public_params(const SOVAPublicParams &public_params)
        {
            validate_batch_params(public_params.params);
            size_t num_buckets = public_params.pbc_public_params.num_buckets;
            if (num_buckets == 0)
            {
                throw std::invalid_argument("batch public params are not initialized");
            }
            if (public_params.bucket_public_params.size() != num_buckets)
            {
                throw std::invalid_argument("bucket public params size mismatch");
            }
            if (public_params.bucket_layouts.size() != num_buckets)
            {
                throw std::invalid_argument("bucket layout metadata size mismatch");
            }
        }

        void validate_batch_server_state(
            const SOVAPublicParams &public_params,
            const SOVAServerState &server_state)
        {
            size_t num_buckets = public_params.pbc_public_params.num_buckets;
            if (server_state.bucket_server_states.size() != num_buckets)
            {
                throw std::invalid_argument("bucket server states size mismatch");
            }
        }

        void validate_context_limbs(const SEALContext &context)
        {
            const size_t limbs = context.first_context_data()->parms().coeff_modulus().size();
            if (limbs < accumulated_limbs)
            {
                throw std::invalid_argument(
                    "the coefficient modulus must have at least two primes");
            }
        }

        size_t choose_depth(size_t max_bucket_size, size_t record_size, size_t requested)
        {
            if (requested != 0)
            {
                return requested;
            }
            size_t best = 1;
            size_t best_cost = record_size + std::max<size_t>(1, max_bucket_size);
            for (size_t d = 2; d <= std::max<size_t>(1, max_bucket_size); d++)
            {
                size_t cost = d * record_size + ceil_div(std::max<size_t>(1, max_bucket_size), d);
                if (cost < best_cost)
                {
                    best = d;
                    best_cost = cost;
                }
            }
            return best;
        }

        uint64_t switch_u32_to_plain(uint32_t value, uint64_t plain_modulus)
        {
            __uint128_t scaled = static_cast<__uint128_t>(value) * plain_modulus + lwe_modulus / 2;
            return static_cast<uint64_t>(scaled / lwe_modulus) % plain_modulus;
        }

        void pack_switched_hint(
            const std::vector<uint32_t> &source,
            uint64_t plain_modulus,
            SOVAPackedHint &destination)
        {
            constexpr size_t bit_width = 17;
            destination.size = source.size();
            destination.words.assign(ceil_div(source.size() * bit_width, size_t(64)), 0);
            for (size_t i = 0; i < source.size(); i++)
            {
                uint64_t value = switch_u32_to_plain(source[i], plain_modulus);
                size_t bit = i * bit_width;
                size_t word = bit >> 6;
                size_t shift = bit & 63;
                destination.words[word] |= value << shift;
                if (shift > 64 - bit_width)
                {
                    destination.words[word + 1] |= value >> (64 - shift);
                }
            }
        }

        uint64_t unpack_switched_hint(const uint64_t *__restrict__ words, size_t index)
        {
            constexpr size_t bit_width = 17;
            constexpr uint64_t mask = (uint64_t(1) << bit_width) - 1;
            size_t bit = index * bit_width;
            size_t word = bit >> 6;
            size_t shift = bit & 63;
            uint64_t value = words[word] >> shift;
            if (shift > 64 - bit_width)
            {
                value |= words[word + 1] << (64 - shift);
            }
            return value & mask;
        }

        uint64_t decode_lwe_slot(uint64_t value, uint64_t modulus, uint64_t message_modulus)
        {
            uint64_t delta = (modulus + message_modulus / 2) / message_modulus;
            return ((value + delta / 2) / delta) % message_modulus;
        }

        void sample_ternary(size_t size, std::vector<int64_t> &secret)
        {
            std::mt19937 generator(std::random_device{}());
            std::uniform_int_distribution<int> distribution(-1, 1);
            secret.resize(size);
            for (auto &value : secret)
            {
                value = distribution(generator);
            }
        }

        void compute_response_vector(
            const std::vector<uint64_t> &database,
            size_t rows,
            size_t cols,
            const std::vector<uint32_t> &query,
            std::vector<uint32_t> &response)
        {
            response.assign(rows, 0);
            for (size_t row = 0; row < rows; row++)
            {
                uint32_t sum = 0;
                for (size_t col = 0; col < cols; col++)
                {
                    sum += static_cast<uint32_t>(database[row * cols + col]) * query[col];
                }
                response[row] = sum;
            }
        }

        void compute_response_vector_fast(
            const PackedDatabase &packed,
            const std::vector<uint32_t> &query,
            std::vector<uint32_t> &response)
        {
            std::vector<uint32_t> padded_query(packed.padded_cols, 0);
            std::copy(query.begin(), query.end(), padded_query.begin());
            std::vector<uint32_t> padded_response(packed.padded_rows, 0);
            matMulVecPacked(
                padded_response.data(), packed.data.data(), padded_query.data(),
                packed.padded_rows, packed.packed_cols);
            response.assign(padded_response.begin(), padded_response.begin() + packed.rows);
        }

        struct SOVAAnswerOnlineState
        {
            std::vector<Ciphertext> row_selectors;
            std::vector<SOVAComponentBuffer> conversion_c0_pages;
            RelinKeys relin_keys;
        };

        using WideAccumulator = unsigned __int128;

        using AccumulationScratch = std::vector<WideAccumulator>;

        uint64_t reduce_wide(WideAccumulator value, const Modulus &modulus)
        {
            uint64_t words[2]{ static_cast<uint64_t>(value), static_cast<uint64_t>(value >> 64) };
            return seal::util::barrett_reduce_128(words, modulus);
        }

        void accumulate_ntt_limb_scalar(
            const std::vector<std::vector<uint64_t>> &cipher_components,
            const uint64_t *diagonals, size_t stride, size_t limb,
            size_t N, const Modulus &modulus, uint64_t *destination,
            AccumulationScratch &sums)
        {
            std::fill(sums.begin(), sums.end(), WideAccumulator(0));
            const size_t offset = limb * N;
            for (size_t k = 0; k < cipher_components.size(); k++)
            {
                const uint64_t *__restrict__ cipher = cipher_components[k].data() + offset;
                const uint64_t *__restrict__ plain = diagonals + k * stride + offset;
                for (size_t i = 0; i < N; i++)
                {
                    sums[i] += static_cast<WideAccumulator>(cipher[i]) * plain[i];
                }
            }
            uint64_t *__restrict__ output = destination;
            for (size_t i = 0; i < N; i++)
            {
                output[i] = reduce_wide(sums[i], modulus);
            }
        }

        void accumulate_ntt_page(
            const std::vector<std::vector<uint64_t>> &cipher_components,
            const std::vector<uint64_t> &diagonals,
            const SEALContext::ContextData &context_data,
            std::vector<uint64_t> &destination,
            AccumulationScratch &scratch)
        {
            const auto &parms = context_data.parms();
            const size_t N = parms.poly_modulus_degree();
            const auto &moduli = parms.coeff_modulus();
            const size_t stride = N * moduli.size();

            destination.assign(stride, 0);
            scratch.resize(N);
            accumulate_ntt_limb_scalar(
                cipher_components, diagonals.data(), stride, 0,
                N, moduli[0], destination.data(), scratch);

            accumulate_ntt_limb_scalar(
                cipher_components, diagonals.data(), stride, 1,
                N, moduli[1], destination.data() + N, scratch);
        }

        void assemble_data_ciphertext_from_ntt(
            const std::vector<uint64_t> &c0, const std::vector<uint64_t> &c1,
            size_t data_limbs, const SEALContext &context, Ciphertext &destination);

        void LWEsToSIMDFinalize(
            const SOVAAnswerPrecompState &offline_state,
            const SOVAAnswerOnlineState &online_state,
            size_t page_index,
            const Plaintext &simplepir_b,
            const SEALContext &context,
            Evaluator &evaluator,
            Ciphertext &destination)
        {
            const auto &online_c0 = online_state.conversion_c0_pages[page_index].data;
            const auto &offline_c1 = offline_state.conversion_c1_pages[page_index].data;
            assemble_data_ciphertext_from_ntt(
                online_c0, offline_c1, accumulated_limbs, context, destination);
            evaluator.add_plain_inplace(destination, simplepir_b);
        }

        void save_crs_ciphertext(
            const Encryptor &encryptor, const Plaintext &plain,
            const prng_seed_type &public_seed, std::vector<seal_byte> &destination)
        {
            Ciphertext seeded;
            encryptor.encrypt_symmetric_with_public_seed(plain, public_seed, seeded);
            destination.resize(static_cast<size_t>(seeded.save_size(compr_mode_type::none)));
            destination.resize(static_cast<size_t>(
                seeded.save(destination.data(), destination.size(), compr_mode_type::none)));
        }

        void load_seeded_ciphertext(
            const SEALContext &context, const std::vector<seal_byte> &source, Ciphertext &destination)
        {
            destination.load(context, source.data(), source.size());
        }

        template <typename T>
        T expand_seeded_object(const T &source, const SEALContext &context)
        {
            std::stringstream stream(std::ios::in | std::ios::out | std::ios::binary);
            source.save(stream, compr_mode_type::none);
            stream.seekg(0);
            T result;
            result.load(context, stream);
            return result;
        }

        void zero_cipher_component(Ciphertext &ciphertext, size_t component)
        {
            std::fill_n(
                ciphertext.data(component),
                ciphertext.poly_modulus_degree() * ciphertext.coeff_modulus_size(), uint64_t(0));
        }

        size_t split_prestore_words(const SEALContext &context)
        {
            const auto &parms = context.first_context_data()->parms();
            const size_t N = parms.poly_modulus_degree();
            const size_t limbs = parms.coeff_modulus().size();
            return N * limbs * (limbs + 1);
        }

        void component_to_ntt(
            const Ciphertext &ciphertext, size_t component, const SEALContext &context,
            std::vector<uint64_t> &destination)
        {
            const auto context_data = context.get_context_data(ciphertext.parms_id());
            const size_t N = ciphertext.poly_modulus_degree();
            const size_t limbs = ciphertext.coeff_modulus_size();
            destination.assign(
                ciphertext.data(component), ciphertext.data(component) + N * limbs);
            seal::util::ntt_negacyclic_harvey(
                seal::util::RNSIter(destination.data(), N), limbs,
                seal::util::iter(context_data->small_ntt_tables()));
        }
        
	void assemble_data_ciphertext_from_ntt(
            const std::vector<uint64_t> &c0, const std::vector<uint64_t> &c1,
            size_t data_limbs, const SEALContext &context, Ciphertext &destination)
        {
            const auto context_data = context.first_context_data();
            const size_t N = context_data->parms().poly_modulus_degree();
            const size_t limbs = context_data->parms().coeff_modulus().size();
            const size_t data_limb_count = std::min(data_limbs, limbs);
            destination.resize(context, context.first_parms_id(), 2);
            destination.is_ntt_form() = false;
            destination.scale() = 1.0;
            destination.correction_factor() = 1;
            std::copy(c0.begin(), c0.end(), destination.data(0));
            std::copy(c1.begin(), c1.end(), destination.data(1));

            if (data_limb_count == 0)
            {
                return;
            }

            auto tables = seal::util::iter(context_data->small_ntt_tables());
            const std::vector<uint64_t> *sources[2]{ &c0, &c1 };
            for (size_t component = 0; component < 2; component++)
            {
                const std::vector<uint64_t> &source = *sources[component];
                const bool all_zero = std::all_of(
                    source.begin(), source.end(),
                    [](uint64_t value) { return value == 0; });
                if (all_zero)
                {
                    continue;
                }
                seal::util::inverse_ntt_negacyclic_harvey(
                    seal::util::RNSIter(destination.data(component), N),
                    data_limb_count, tables);
            }
        }
    }

    void SOVADBSetup(
        const std::vector<std::vector<uint8_t>> &database,
        const SOVAParams &params,
        const SEALContext &context,
        SOVAPublicParams &public_params,
        SOVAServerState &server_state)
    {
        validate_batch_params(params);
        validate_context_limbs(context);

        public_params = {};
        server_state = {};
        public_params.params = params;
        std::random_device crs_random;
        public_params.simd_crs_seed =
            (static_cast<uint64_t>(crs_random()) << 32) ^ static_cast<uint64_t>(crs_random());

        std::vector<uint64_t> indices(database.size());
        std::iota(indices.begin(), indices.end(), 0);
        BuildPBCBuckets(indices, params.pbc_params, public_params.pbc_public_params, server_state.pbc_server_state);

        const size_t bucket_count = public_params.pbc_public_params.num_buckets;
        const size_t slot_count = context.key_context_data()->parms().poly_modulus_degree();

        public_params.bucket_depth = choose_depth(
            public_params.pbc_public_params.max_bucket_size,
            params.record_size_bytes,
            params.bucket_depth);
        build_bucket_partitions(
            bucket_count, slot_count, params.record_size_bytes,
            public_params.bucket_partitions, public_params.num_pages);
        public_params.bucket_layouts.resize(bucket_count);
        public_params.bucket_public_params.resize(bucket_count);
        server_state.bucket_server_states.resize(bucket_count);
        server_state.switched_hint_matrices.resize(bucket_count);

        for (size_t bucket = 0; bucket < bucket_count; bucket++)
        {
            const size_t actual = server_state.pbc_server_state.actual_bucket_sizes[bucket];
            const size_t cols = std::max<size_t>(1, ceil_div(std::max<size_t>(1, actual), public_params.bucket_depth));
            BatchBucketLayout layout;
            layout.item_slots = actual;
            layout.items_per_column = public_params.bucket_depth;
            layout.rows = public_params.bucket_depth * params.record_size_bytes;
            layout.cols = cols;
            layout.record_size_bytes = params.record_size_bytes;

            std::vector<uint64_t> matrix(layout.rows * layout.cols, params.pbc_params.padding_value);
            for (size_t item = 0; item < actual; item++)
            {
                const size_t col = item / public_params.bucket_depth;
                const size_t row_slot = item % public_params.bucket_depth;
                const auto &record = database[server_state.pbc_server_state.bucket_global_indices[bucket][item]];
                for (size_t byte = 0; byte < params.record_size_bytes; byte++)
                {
                    matrix[(row_slot * params.record_size_bytes + byte) * cols + col] = record[byte];
                }
            }
            public_params.bucket_layouts[bucket] = layout;

            SOVASimplePIRParams single;
            single.rows = layout.rows;
            single.cols = layout.cols;
            single.lwe_dimension = params.lwe_dimension;
            single.record_plain_modulus = params.record_plain_modulus;
            single.benchmark_randomize_hint_matrix = params.benchmark_randomize_hint_matrix;
            simplepir_setup(
                matrix, single, public_params.bucket_public_params[bucket],
                server_state.bucket_server_states[bucket]);
            auto &single_state = server_state.bucket_server_states[bucket];
            pack_switched_hint(
                single_state.hint_matrix, sova_plain_modulus,
                server_state.switched_hint_matrices[bucket]);
            single_state.hint_matrix.clear();
            single_state.hint_matrix.shrink_to_fit();
        }
    }

    void SOVAAnswerPrecompute(
        const SOVAPublicParams &public_params,
        SOVAServerState &server_state,
        const SEALContext &context,
        BatchEncoder &batch_encoder,
        Evaluator &evaluator,
        SOVAAnswerPrecompState &precomp_state)
    {
        validate_batch_public_params(public_params);
        validate_batch_server_state(public_params, server_state);
        validate_context_limbs(context);
        if (server_state.switched_hint_matrices.size() !=
            public_params.pbc_public_params.num_buckets)
        {
            throw std::invalid_argument(
                "packed hint matrices are not available; run SOVADBSetup again before "
                "precomputing the answer phase");
        }
        const size_t N = context.first_context_data()->parms().poly_modulus_degree();
        const size_t n = public_params.params.lwe_dimension;
        const size_t d = public_params.bucket_depth;
        const size_t U = public_params.num_pages;
        const size_t kappa = public_params.params.record_size_bytes;
        const size_t limbs = context.first_context_data()->parms().coeff_modulus().size();
        const size_t component_words = N * limbs;
        const size_t prestore_words = split_prestore_words(context);

        precomp_state = {};
        precomp_state.parms_id = context.first_parms_id();

        KeyGenerator crs_keygen(context);
        Encryptor crs_encryptor(context, crs_keygen.secret_key());
        std::vector<uint64_t> zeros(N, 0);
        Plaintext zero_plain;
        batch_encoder.encode(zeros, zero_plain);

        Ciphertext seeded_evaluation_a;
        crs_encryptor.encrypt_symmetric_with_public_seed(
            zero_plain,
            derive_crs_seed(public_params.simd_crs_seed, crs_domain_evaluation, 0),
            seeded_evaluation_a);
        Ciphertext evaluation_a = expand_seeded_object(seeded_evaluation_a, context);
        zero_cipher_component(evaluation_a, 0);

        const auto galois_elts = sova_galois_elts(context, n);
        auto galois_seeds = sova_key_seeds(
            public_params.simd_crs_seed, crs_domain_galois,
            galois_elts.size() * limbs);
        GaloisKeys seeded_galois_a =
            crs_keygen.create_galois_keys_with_public_seeds(galois_elts, galois_seeds);
        GaloisKeys galois_a = expand_seeded_object(seeded_galois_a, context);
        for (auto &key_vector : galois_a.data())
        {
            for (auto &key : key_vector)
            {
                zero_cipher_component(key.data(), 0);
            }
        }

        RelinKeys relin_a;
        if (d > 1)
        {
            auto relin_seeds = sova_key_seeds(
                public_params.simd_crs_seed, crs_domain_relinearization, limbs);
            relin_a = expand_seeded_object(
                crs_keygen.create_relin_keys_with_public_seeds(relin_seeds), context);
            for (auto &key_vector : relin_a.data())
            {
                for (auto &key : key_vector)
                {
                    zero_cipher_component(key.data(), 0);
                }
            }
        }

        std::vector<Ciphertext> rotations(n);
        std::vector<std::vector<uint64_t>> rotation_c1_ntt(n);
        precomp_state.rotation_prestore.resize(n);
        rotations[0] = std::move(evaluation_a);
        component_to_ntt(rotations[0], 1, context, rotation_c1_ntt[0]);
        auto galois_tool = context.key_context_data()->galois_tool();
        for (size_t block = 1; block < n; block <<= 1)
        {
            const uint32_t galois_elt =
                galois_tool->get_elt_from_step(static_cast<int>(block));
            for (size_t offset = 0; offset < block && offset + block < n; offset++)
            {
                const size_t child = offset + block;
                auto &prestore = precomp_state.rotation_prestore[child].data;
                prestore.resize(prestore_words);
                seal::util::PolyIter prestore_iter(prestore.data(), N, limbs);
                evaluator.apply_galois_a_precompute(
                    rotations[offset], galois_elt, prestore_iter, galois_a,
                    rotations[child]);
                zero_cipher_component(rotations[child], 0);
                component_to_ntt(rotations[child], 1, context, rotation_c1_ntt[child]);
            }
        }

        precomp_state.conversion_diagonal_ntt_pages.resize(d * U);
        precomp_state.conversion_c1_pages.resize(d * U);
        std::vector<uint64_t> diagonal(N, 0);
        AccumulationScratch accumulation_scratch;
        const auto &data_context = *context.first_context_data();
        const SOVAPackedHint *switched_hints = server_state.switched_hint_matrices.data();
        for (const auto &partition : public_params.bucket_partitions)
        {
            const size_t G = partition.bucket_count;
            const size_t J = partition.slots_per_bucket;
            for (size_t h = 0; h < d; h++)
            {
                for (size_t local_u = 0; local_u < partition.num_pages; local_u++)
                {
                    const size_t page = partition.response_page_offset + local_u;
                    const size_t output = h * U + page;
                    auto &diagonal_page =
                        precomp_state.conversion_diagonal_ntt_pages[output].data;
                    diagonal_page.resize(n * component_words);
                    
		    const size_t covered_rows = std::min(J, kappa > local_u * J ?
                        kappa - local_u * J : size_t(0));
                    for (size_t k = 0; k < n; k++)
                    {
                        if (covered_rows < J)
                        {
                            std::fill(
                                diagonal.begin() + covered_rows * G, diagonal.end(), 0);
                        }
                        for (size_t a = 0; a < covered_rows; a++)
                        {
                            const size_t byte = local_u * J + a;
                            const size_t row = h * kappa + byte;
                            for (size_t local_bucket = 0; local_bucket < G; local_bucket++)
                            {
                                const size_t slot = a * G + local_bucket;
                                const size_t bucket = partition.bucket_begin + local_bucket;
                                const size_t secret_col = (slot + k) % n;
                                diagonal[slot] = unpack_switched_hint(
                                    switched_hints[bucket].words.data(), row * n + secret_col);
                            }
                        }
                        Plaintext diagonal_ntt;
                        batch_encoder.encode(diagonal, diagonal_ntt);
                        evaluator.transform_to_ntt_inplace(
                            diagonal_ntt, context.first_parms_id());
                        std::copy_n(
                            diagonal_ntt.data(), component_words,
                            diagonal_page.data() + k * component_words);
                    }
                    accumulate_ntt_page(
                        rotation_c1_ntt, diagonal_page, data_context,
                        precomp_state.conversion_c1_pages[output].data,
                        accumulation_scratch);
                }
            }
        }

        if (d > 1)
        {
            const size_t selector_count = public_params.bucket_partitions.size() * d;
            std::vector<Ciphertext> selector_a(selector_count);
            for (size_t selector = 0; selector < selector_count; selector++)
            {
                Ciphertext seeded;
                crs_encryptor.encrypt_symmetric_with_public_seed(
                    zero_plain,
                    derive_crs_seed(public_params.simd_crs_seed, crs_domain_selector, selector),
                    seeded);
                selector_a[selector] = expand_seeded_object(seeded, context);
                zero_cipher_component(selector_a[selector], 0);
            }

            precomp_state.row_relin_c1_pages.resize(U);
            precomp_state.row_relin_prestore.resize(U);
            std::vector<uint64_t> zero_component(component_words, 0);
            for (size_t partition_index = 0;
                 partition_index < public_params.bucket_partitions.size(); partition_index++)
            {
                const auto &partition = public_params.bucket_partitions[partition_index];
                for (size_t local_u = 0; local_u < partition.num_pages; local_u++)
                {
                    const size_t page = partition.response_page_offset + local_u;
                    Ciphertext c2_sum;
                    bool initialized = false;
                    for (size_t h = 0; h < d; h++)
                    {
                        Ciphertext conversion_a;
                        assemble_data_ciphertext_from_ntt(
                            zero_component,
                            precomp_state.conversion_c1_pages[h * U + page].data,
                            accumulated_limbs, context, conversion_a);
                        Ciphertext product;
                        evaluator.multiply(
                            conversion_a, selector_a[partition_index * d + h], product);
                        if (!initialized)
                        {
                            c2_sum = std::move(product);
                            initialized = true;
                        }
                        else
                        {
                            evaluator.add_inplace(c2_sum, product);
                        }
                    }

                    std::vector<uint64_t> target(
                        c2_sum.data(2), c2_sum.data(2) + component_words);
                    Ciphertext relin_a_result;
                    relin_a_result.resize(context, context.first_parms_id(), 2);
                    relin_a_result.is_ntt_form() = false;
                    relin_a_result.scale() = 1.0;
                    relin_a_result.correction_factor() = 1;
                    std::fill_n(relin_a_result.data(), component_words * 2, uint64_t(0));
                    auto &prestore = precomp_state.row_relin_prestore[page].data;
                    prestore.resize(prestore_words);
                    seal::util::PolyIter prestore_iter(prestore.data(), N, limbs);
                    evaluator.switch_key_inplace_a_precompute(
                        relin_a_result, seal::util::ConstRNSIter(target.data(), N),
                        prestore_iter, relin_a, 0, MemoryManager::GetPool());
                    auto &relin_c1 = precomp_state.row_relin_c1_pages[page].data;
                    relin_c1.assign(
                        relin_a_result.data(1), relin_a_result.data(1) + component_words);
                }
            }
        }
        std::vector<SOVAPackedHint>().swap(server_state.switched_hint_matrices);

        precomp_state.initialized = true;
    }

    void SOVAQuery(
        const SOVAPublicParams &public_params,
        const std::vector<size_t> &batch_indices,
        const SEALContext &context,
        BatchEncoder &batch_encoder,
        KeyGenerator &keygen,
        Encryptor &encryptor,
        SOVAQueryMessage &query,
        SOVAClientState &client_state,
        SOVAQueryProfile *profile)
    {
        using Clock = std::chrono::steady_clock;
        using Milliseconds = std::chrono::duration<double, std::milli>;
        using Nanoseconds = std::chrono::nanoseconds;

        Nanoseconds seed_elapsed{};

        double pbc_ms = 0.0;
        double simplepir_ms = 0.0;
        double lwes_to_simd_key_ms = 0.0;
        double row_selector_ms = 0.0;
        double evaluation_keys_ms = 0.0;

        if (profile)
        {
            *profile = {};
        }

        const auto total_start = Clock::now();

        {
            // Restore the previous counter on normal return or exception.
            // The counter is active only during this SOVAQuery invocation.
            struct RestoreSeedCounter
            {
                Nanoseconds *previous;

                ~RestoreSeedCounter()
                {
                    seal::sova_seed_elapsed = previous;
                }
            } restore_seed_counter{seal::sova_seed_elapsed};

            seal::sova_seed_elapsed = &seed_elapsed;

            // Record a stage after subtracting its nested Seed time.
            // This keeps Seed disjoint from the other four reported modules.
            auto measure = [&](double &destination_ms, auto &&operation)
            {
                const auto seed_before = seed_elapsed;
                const auto start = Clock::now();

                operation();

                const auto end = Clock::now();
                destination_ms +=
                    Milliseconds(end - start).count() -
                    Milliseconds(seed_elapsed - seed_before).count();
            };

            validate_batch_public_params(public_params);

            query = {};
            client_state = {};
            client_state.batch_indices = batch_indices;

            // ------------------------------------------------------------
            // PBC: assign the requested indices to buckets.
            // ------------------------------------------------------------
            measure(pbc_ms, [&]
            {
                AssignBatchIndicesToBuckets(
                    public_params.pbc_public_params,
                    batch_indices,
                    client_state.query_plan);
            });

            // ------------------------------------------------------------
            // SimplePIR: sample the LWE secret.
            // ------------------------------------------------------------
            measure(simplepir_ms, [&]
            {
                sample_ternary(
                    public_params.params.lwe_dimension,
                    client_state.query_secret);
            });

            const size_t N = batch_encoder.slot_count();
            const size_t n = public_params.params.lwe_dimension;
            const size_t B = public_params.pbc_public_params.num_buckets;
            const size_t d = public_params.bucket_depth;

            const uint64_t p =
                context.first_context_data()->parms().plain_modulus().value();

            std::vector<uint64_t> values;
            Plaintext plain;

            measure(lwes_to_simd_key_ms, [&]
            {
                values.resize(N);

                for (size_t slot = 0; slot < N; slot++)
                {
                    const int64_t value =
                        client_state.query_secret[slot % n];

                    values[slot] =
                        value < 0 ? p - 1 : static_cast<uint64_t>(value);
                }

                batch_encoder.encode(values, plain);

                prng_seed_type evaluation_seed{};
                {
                    seal::SOVASeedTimer seed_timer;

                    evaluation_seed = derive_crs_seed(
                        public_params.simd_crs_seed,
                        crs_domain_evaluation,
                        0);
                }

                save_crs_ciphertext(
                    encryptor,
                    plain,
                    evaluation_seed,
                    query.evaluation_key);
            });
	    
	    std::vector<size_t> row_choices;

            measure(simplepir_ms, [&]
            {
                row_choices.assign(B, 0);
                query.bucket_queries.resize(B);

                std::mt19937_64 generator(std::random_device{}());

                for (size_t bucket = 0; bucket < B; bucket++)
                {
                    const auto &layout = public_params.bucket_layouts[bucket];
                    const size_t capacity = d * layout.cols;

                    size_t item = 0;
                    const size_t position =
                        client_state.query_plan.bucket_to_query_position[bucket];

                    if (position != pbc_invalid_index)
                    {
                        item = client_state.query_plan
                                   .assignments[position]
                                   .placement.slot_index;
                    }
                    else
                    {
                        std::uniform_int_distribution<size_t> distribution(
                            0, capacity - 1);

                        item = distribution(generator);
                    }

                    row_choices[bucket] = item % d;

                    auto &bucket_query = query.bucket_queries[bucket];
                    bucket_query.bucket_index = bucket;

                    const auto &bucket_public =
                        public_params.bucket_public_params[bucket];

                    build_query_vector_from_seed(
                        bucket_public.public_matrix_seed,
                        layout.cols,
                        n,
                        client_state.query_secret,
                        item / d,
                        public_params.params.record_plain_modulus,
                        bucket_query.query_vector);
                }
            });

            if (d > 1)
            {
                measure(row_selector_ms, [&]
                {
                    query.row_selectors.resize(
                        public_params.bucket_partitions.size() * d);

                    for (size_t partition_index = 0;
                         partition_index < public_params.bucket_partitions.size();
                         partition_index++)
                    {
                        const auto &partition =
                            public_params.bucket_partitions[partition_index];

                        const size_t G = partition.bucket_count;
                        const size_t J = partition.slots_per_bucket;

                        for (size_t h = 0; h < d; h++)
                        {
                            std::fill(values.begin(), values.end(), 0);

                            for (size_t a = 0; a < J; a++)
                            {
                                for (size_t local_bucket = 0;
                                     local_bucket < G;
                                     local_bucket++)
                                {
                                    const size_t bucket =
                                        partition.bucket_begin + local_bucket;

                                    values[a * G + local_bucket] =
                                        static_cast<uint64_t>(
                                            row_choices[bucket] == h);
                                }
                            }

                            const size_t selector = partition_index * d + h;

                            batch_encoder.encode(values, plain);

                            prng_seed_type selector_seed{};
                            {
                                seal::SOVASeedTimer seed_timer;

                                selector_seed = derive_crs_seed(
                                    public_params.simd_crs_seed,
                                    crs_domain_selector,
                                    selector);
                            }

                            save_crs_ciphertext(
                                encryptor,
                                plain,
                                selector_seed,
                                query.row_selectors[selector]);
                        }
                    }
                });
            }

            measure(evaluation_keys_ms, [&]
            {
                const auto galois_elts = sova_galois_elts(context, n);

                const size_t limbs =
                    context.first_context_data()->parms()
                        .coeff_modulus().size();

                std::vector<prng_seed_type> galois_seeds;
                {
                    seal::SOVASeedTimer seed_timer;

                    galois_seeds = sova_key_seeds(
                        public_params.simd_crs_seed,
                        crs_domain_galois,
                        galois_elts.size() * limbs);
                }

                auto seeded_galois_keys =
                    keygen.create_galois_keys_with_public_seeds(
                        galois_elts, galois_seeds);

                query.galois_keys.resize(static_cast<size_t>(
                    seeded_galois_keys.save_size(compr_mode_type::none)));

                query.galois_keys.resize(static_cast<size_t>(
                    seeded_galois_keys.save(
                        query.galois_keys.data(),
                        query.galois_keys.size(),
                        compr_mode_type::none)));

                if (d > 1)
                {
                    std::vector<prng_seed_type> relin_seeds;
                    {
                        seal::SOVASeedTimer seed_timer;

                        relin_seeds = sova_key_seeds(
                            public_params.simd_crs_seed,
                            crs_domain_relinearization,
                            limbs);
                    }

                    auto seeded_relin_keys =
                        keygen.create_relin_keys_with_public_seeds(
                            relin_seeds);

                    query.relin_keys.resize(static_cast<size_t>(
                        seeded_relin_keys.save_size(compr_mode_type::none)));

                    query.relin_keys.resize(static_cast<size_t>(
                        seeded_relin_keys.save(
                            query.relin_keys.data(),
                            query.relin_keys.size(),
                            compr_mode_type::none)));
                }
            });
        }

        const double total_ms =
            Milliseconds(Clock::now() - total_start).count();

        if (profile)
        {
            profile->pbc_ms = pbc_ms;
            profile->seed_ms = Milliseconds(seed_elapsed).count();
            profile->simplepir_ms = simplepir_ms;
            profile->lwes_to_simd_key_ms = lwes_to_simd_key_ms;
            profile->row_selector_ms = row_selector_ms;
            profile->evaluation_keys_ms = evaluation_keys_ms;
            profile->total_ms = total_ms;
        }
    }

    static void lwes_to_simd_online_b(
        const SOVAPublicParams &public_params,
        const SOVAAnswerPrecompState &answer_precomp_state,
        const SOVAQueryMessage &query,
        const SEALContext &context,
        Evaluator &evaluator,
        SOVAAnswerOnlineState &online_state)
    {
        const size_t N = context.first_context_data()->parms().poly_modulus_degree();
        const size_t n = public_params.params.lwe_dimension;
        const size_t d = public_params.bucket_depth;
        const size_t U = public_params.num_pages;
        const size_t selector_count = public_params.bucket_partitions.size() * d;
        const size_t limbs = context.first_context_data()->parms().coeff_modulus().size();

        GaloisKeys galois_keys;
        galois_keys.load(context, query.galois_keys.data(), query.galois_keys.size());
        Ciphertext evaluation_key;
        load_seeded_ciphertext(context, query.evaluation_key, evaluation_key);
        zero_cipher_component(evaluation_key, 1);

        online_state = {};
        if (d > 1)
        {
            if (query.row_selectors.size() != selector_count || query.relin_keys.empty())
            {
                throw std::invalid_argument("missing row-selection query material");
            }
            online_state.relin_keys.load(
                context, query.relin_keys.data(), query.relin_keys.size());
            online_state.row_selectors.resize(selector_count);
            for (size_t selector = 0; selector < selector_count; selector++)
            {
                load_seeded_ciphertext(
                    context, query.row_selectors[selector],
                    online_state.row_selectors[selector]);
            }
        }
        else if (!query.row_selectors.empty() || !query.relin_keys.empty())
        {
            throw std::invalid_argument("depth-1 queries must omit row-selection material");
        }

        std::vector<Ciphertext> rotations(n);
        std::vector<std::vector<uint64_t>> rotation_c0_ntt(n);
        rotations[0] = std::move(evaluation_key);
        component_to_ntt(rotations[0], 0, context, rotation_c0_ntt[0]);
        auto galois_tool = context.key_context_data()->galois_tool();
        for (size_t block = 1; block < n; block <<= 1)
        {
            const uint32_t galois_elt =
                galois_tool->get_elt_from_step(static_cast<int>(block));
            for (size_t offset = 0; offset < block && offset + block < n; offset++)
            {
                const size_t child = offset + block;
                auto &prestore = answer_precomp_state.rotation_prestore[child].data;
                seal::util::PolyIter prestore_iter(
                    const_cast<uint64_t *>(prestore.data()), N, limbs);
                evaluator.apply_galois_b_online(
                    rotations[offset], galois_elt, prestore_iter, galois_keys,
                    rotations[child]);
                zero_cipher_component(rotations[child], 1);
                component_to_ntt(rotations[child], 0, context, rotation_c0_ntt[child]);
            }
        }

        online_state.conversion_c0_pages.resize(d * U);
        const auto &data_context = *context.first_context_data();
        AccumulationScratch accumulation_scratch;
        for (size_t output = 0; output < d * U; output++)
        {
            const auto &diagonal_page =
                answer_precomp_state.conversion_diagonal_ntt_pages[output].data;
            accumulate_ntt_page(
                rotation_c0_ntt, diagonal_page, data_context,
                online_state.conversion_c0_pages[output].data,
                accumulation_scratch);
        }
    }

    void SOVAAnswer(
        const SOVAPublicParams &public_params,
        const SOVAServerState &server_state,
        const SOVAAnswerPrecompState &answer_precomp_state,
        const SOVAQueryMessage &query,
        const SEALContext &context,
        BatchEncoder &batch_encoder,
        Encryptor &public_encryptor,
        Evaluator &evaluator,
        SOVAResponseMessage &response,
        SOVAAnswerProfile *profile)
    {
        validate_batch_public_params(public_params);
        validate_batch_server_state(public_params, server_state);
        validate_context_limbs(context);
        using clock = std::chrono::steady_clock;
        SOVAAnswerProfile local_profile;
        auto step_start = clock::now();
        SOVAAnswerOnlineState online_state;
        lwes_to_simd_online_b(
            public_params, answer_precomp_state, query, context,
            evaluator, online_state);
        local_profile.lwes_to_simd_online_b_ms =
            std::chrono::duration<double, std::milli>(clock::now() - step_start).count();

        const size_t N = batch_encoder.slot_count();
        const size_t B = public_params.pbc_public_params.num_buckets;
        const size_t U = public_params.num_pages;
        const size_t d = public_params.bucket_depth;
        const size_t kappa = public_params.params.record_size_bytes;
        const uint64_t p = sova_plain_modulus;

        std::vector<std::vector<uint32_t>> bucket_responses(B);
        step_start = clock::now();
        for (size_t bucket = 0; bucket < B; bucket++)
        {
            const auto &state = server_state.bucket_server_states[bucket];
            const auto &query_vector = query.bucket_queries[bucket].query_vector;
            if (!state.packed_database.empty())
            {
                compute_response_vector_fast(state.packed_database, query_vector, bucket_responses[bucket]);
            }
            else
            {
                const size_t rows = state.database.size() / query_vector.size();
                compute_response_vector(
                    state.database, rows, query_vector.size(), query_vector,
                bucket_responses[bucket]);
            }
        }
        local_profile.simplepir_ms =
            std::chrono::duration<double, std::milli>(clock::now() - step_start).count();

        response.pages.resize(U);
        std::vector<uint64_t> values(N, 0);
        Plaintext plain;
        for (size_t partition_index = 0;
             partition_index < public_params.bucket_partitions.size(); partition_index++)
        {
            const auto &partition = public_params.bucket_partitions[partition_index];
            const size_t G = partition.bucket_count;
            const size_t J = partition.slots_per_bucket;
            for (size_t local_u = 0; local_u < partition.num_pages; local_u++)
            {
                const size_t response_page = partition.response_page_offset + local_u;
                Ciphertext page;
                bool initialized = false;
                for (size_t h = 0; h < d; h++)
                {
                    const size_t index = h * U + response_page;

                    step_start = clock::now();
                    std::fill(values.begin(), values.end(), 0);
                    for (size_t a = 0; a < J; a++)
                    {
                        size_t byte = local_u * J + a;
                        if (byte >= kappa)
                        {
                            break;
                        }
                        for (size_t local_bucket = 0; local_bucket < G; local_bucket++)
                        {
                            const size_t bucket = partition.bucket_begin + local_bucket;
                            values[a * G + local_bucket] = switch_u32_to_plain(
                                bucket_responses[bucket][h * kappa + byte], p);
                        }
                    }
                    batch_encoder.encode(values, plain);

                    Ciphertext lwe_to_simd;
                    LWEsToSIMDFinalize(
                        answer_precomp_state, online_state, index, plain,
                        context, evaluator, lwe_to_simd);
                    local_profile.lwes_to_simd_finalize_ms +=
                        std::chrono::duration<double, std::milli>(clock::now() - step_start).count();

                    if (d == 1)
                    {
                        page = std::move(lwe_to_simd);
                        initialized = true;
                        continue;
                    }

                    step_start = clock::now();
                    Ciphertext masked;
                    evaluator.multiply(
                        lwe_to_simd,
                        online_state.row_selectors[partition_index * d + h],
                        masked);
                    masked.resize(context, masked.parms_id(), 2);
                    if (!initialized)
                    {
                        page = std::move(masked);
                        initialized = true;
                    }
                    else
                    {
                        evaluator.add_inplace(page, masked);
                    }
                    local_profile.encrypted_row_selection_ms +=
                        std::chrono::duration<double, std::milli>(clock::now() - step_start).count();
                }
                if (!initialized)
                {
                    public_encryptor.encrypt_zero(response.pages[response_page]);
                }
                else
                {
                    if (d > 1)
                    {
                        step_start = clock::now();
                        auto &prestore =
                            answer_precomp_state.row_relin_prestore[response_page].data;
                        seal::util::PolyIter prestore_iter(
                            const_cast<uint64_t *>(prestore.data()),
                            page.poly_modulus_degree(), page.coeff_modulus_size());
                        evaluator.switch_key_inplace_b_online(
                            page, prestore_iter, online_state.relin_keys, 0,
                            MemoryManager::GetPool());
                        const auto &offline_c1 =
                            answer_precomp_state.row_relin_c1_pages[response_page].data;
                        const auto &moduli = context.first_context_data()->parms().coeff_modulus();
                        const size_t degree = page.poly_modulus_degree();
                        for (size_t limb = 0; limb < moduli.size(); limb++)
                        {
                            for (size_t i = 0; i < degree; i++)
                            {
                                const size_t position = limb * degree + i;
                                page.data(1)[position] = seal::util::add_uint_mod(
                                    page.data(1)[position], offline_c1[position], moduli[limb]);
                            }
                        }
                        local_profile.relinearization_ms +=
                            std::chrono::duration<double, std::milli>(clock::now() - step_start).count();
                    }
                    step_start = clock::now();
                    evaluator.mod_switch_to_next_inplace(page);
                    local_profile.modulus_switch_ms +=
                        std::chrono::duration<double, std::milli>(clock::now() - step_start).count();
                    response.pages[response_page] = std::move(page);
                }
            }
        }
        if (profile)
        {
            *profile = local_profile;
        }
    }

    void SOVAExtract(
        const SOVAPublicParams &public_params,
        const SOVAClientState &client_state,
        const SOVAResponseMessage &response,
        BatchEncoder &batch_encoder,
        Decryptor &decryptor,
        std::vector<std::vector<uint8_t>> &records)
    {
        validate_batch_public_params(public_params);
        const size_t kappa = public_params.params.record_size_bytes;
        std::vector<std::vector<uint64_t>> decoded(response.pages.size());
        for (size_t u = 0; u < response.pages.size(); u++)
        {
            Plaintext plain;
            decryptor.decrypt(response.pages[u], plain);
            batch_encoder.decode(plain, decoded[u]);
        }

        records.assign(client_state.batch_indices.size(), std::vector<uint8_t>(kappa));
        for (const auto &assignment : client_state.query_plan.assignments)
        {
            const size_t bucket = assignment.placement.bucket_index;
            const auto partition_it = std::find_if(
                public_params.bucket_partitions.begin(), public_params.bucket_partitions.end(),
                [bucket](const SOVABucketPartition &partition) {
                    return bucket >= partition.bucket_begin &&
                        bucket < partition.bucket_begin + partition.bucket_count;
                });
            const auto &partition = *partition_it;
            const size_t local_bucket = bucket - partition.bucket_begin;
            const size_t G = partition.bucket_count;
            const size_t J = partition.slots_per_bucket;
            for (size_t byte = 0; byte < kappa; byte++)
            {
                const size_t u = partition.response_page_offset + byte / J;
                const size_t a = byte % J;
                const uint64_t phase = decoded[u][a * G + local_bucket];
                records[assignment.query_position][byte] = static_cast<uint8_t>(
                    decode_lwe_slot(phase, sova_plain_modulus, public_params.params.record_plain_modulus));
            }
        }
    }
}

