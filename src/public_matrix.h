#pragma once

#include "seal/seal.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace sova::pir
{
    void sample_public_matrix_seed(seal::prng_seed_type &seed);

    void compute_hint_matrix_from_seed(
        const std::vector<uint64_t> &database,
        size_t rows,
        size_t cols,
        const seal::prng_seed_type &public_matrix_seed,
        size_t lwe_dimension,
        std::vector<uint32_t> &hint_matrix);

    void sample_random_hint_matrix(
        size_t rows,
        size_t lwe_dimension,
        std::vector<uint32_t> &hint_matrix);

    void build_query_vector_from_seed(
        const seal::prng_seed_type &public_matrix_seed,
        size_t cols,
        size_t lwe_dimension,
        const std::vector<int64_t> &secret,
        size_t target_col,
        uint64_t record_plain_modulus,
        std::vector<uint32_t> &query_vector);
}

