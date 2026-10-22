/*
Derived from public_matrix.cpp in SPIRIT:
"SPIRIT: Batch Hintless Single-server PIR via Stateful Ciphertext Conversion"

Original work: ZHANG, Z. (2026).
Source: https://doi.org/10.5281/zenodo.20528536

The original code is licensed under the Creative Commons Attribution
4.0 International License (CC BY 4.0):
https://creativecommons.org/licenses/by/4.0/

Modifications: Adapted for integration into SOVA.
*/

#include "public_matrix.h"

#include <algorithm>
#include <bit>
#include <stdexcept>

namespace sage::pir
{
    using namespace seal;

    namespace
    {
        constexpr uint64_t lwe_modulus_value = (1ULL << 32);

        std::shared_ptr<UniformRandomGenerator> create_public_matrix_prng(
            const prng_seed_type &seed)
        {
            return UniformRandomGeneratorFactory::DefaultFactory()->create(seed);
        }

        void sample_query_noise(size_t cols, std::vector<uint32_t> &noise)
        {
            auto prng = UniformRandomGeneratorFactory::DefaultFactory()->create();
            noise.resize(cols);
            for (auto &value : noise)
            {
                unsigned char bytes[6];
                prng->generate(6, reinterpret_cast<seal_byte *>(bytes));
                bytes[2] &= 0x1F;
                bytes[5] &= 0x1F;
                int32_t sample = std::popcount(bytes[0]) + std::popcount(bytes[1]) +
                    std::popcount(bytes[2]) - std::popcount(bytes[3]) -
                    std::popcount(bytes[4]) - std::popcount(bytes[5]);
                value = static_cast<uint32_t>(sample);
            }
        }

        void sample_uniform_u32(
            const std::shared_ptr<UniformRandomGenerator> &prng,
            size_t count, uint32_t *destination)
        {
            prng->generate(count * sizeof(uint32_t),
                reinterpret_cast<seal_byte *>(destination));
        }
    }

    void sample_public_matrix_seed(prng_seed_type &seed)
    {
        random_bytes(reinterpret_cast<seal_byte *>(seed.data()), prng_seed_byte_count);
    }

    void compute_hint_matrix_from_seed(
        const std::vector<uint64_t> &database,
        size_t rows,
        size_t cols,
        const prng_seed_type &public_matrix_seed,
        size_t lwe_dimension,
        std::vector<uint32_t> &hint_matrix)
    {
        if (database.size() != rows * cols)
        {
            throw std::invalid_argument("database size must equal rows * cols");
        }

        hint_matrix.assign(rows * lwe_dimension, 0);
        if (rows == 0 || cols == 0 || lwe_dimension == 0)
        {
            return;
        }

        constexpr size_t cache_block_bytes = 128 * 1024;
        const size_t block_rows = std::max<size_t>(
            1, cache_block_bytes / (lwe_dimension * sizeof(uint32_t)));
        const size_t block_cols = block_rows;

        auto public_matrix_prng = create_public_matrix_prng(public_matrix_seed);
        std::vector<uint32_t> public_matrix_chunk(block_cols * lwe_dimension);

        for (size_t col_begin = 0; col_begin < cols; col_begin += block_cols)
        {
            const size_t col_end = std::min(cols, col_begin + block_cols);
            for (size_t col = col_begin; col < col_end; col++)
            {
                sample_uniform_u32(
                    public_matrix_prng, lwe_dimension,
                    public_matrix_chunk.data() + (col - col_begin) * lwe_dimension);
            }

            for (size_t row_begin = 0; row_begin < rows; row_begin += block_rows)
            {
                const size_t row_end = std::min(rows, row_begin + block_rows);
                for (size_t col = col_begin; col < col_end; col++)
                {
                    const uint32_t *__restrict__ public_row =
                        public_matrix_chunk.data() + (col - col_begin) * lwe_dimension;
                    for (size_t row = row_begin; row < row_end; row++)
                    {
                        const uint32_t db_value = static_cast<uint32_t>(database[row * cols + col]);
                        if (db_value == 0)
                        {
                            continue;
                        }

                        uint32_t *__restrict__ hint_row = hint_matrix.data() + row * lwe_dimension;
                        for (size_t j = 0; j < lwe_dimension; j++)
                        {
                            hint_row[j] += db_value * public_row[j];
                        }
                    }
                }
            }
        }
    }

    void sample_random_hint_matrix(
        size_t rows,
        size_t lwe_dimension,
        std::vector<uint32_t> &hint_matrix)
    {
        hint_matrix.assign(rows * lwe_dimension, 0);
        if (hint_matrix.empty())
        {
            return;
        }

        auto prng = UniformRandomGeneratorFactory::DefaultFactory()->create();
        sample_uniform_u32(prng, hint_matrix.size(), hint_matrix.data());
    }

    void build_query_vector_from_seed(
        const prng_seed_type &public_matrix_seed,
        size_t cols,
        size_t lwe_dimension,
        const std::vector<int64_t> &secret,
        size_t target_col,
        uint64_t record_plain_modulus,
        std::vector<uint32_t> &query_vector)
    {
        if (secret.size() != lwe_dimension)
        {
            throw std::invalid_argument("query secret size must equal lwe_dimension");
        }
        if (target_col >= cols)
        {
            throw std::invalid_argument("target column out of range");
        }

        query_vector.assign(cols, 0);

        const uint32_t delta = static_cast<uint32_t>(
            (lwe_modulus_value + record_plain_modulus / 2) / record_plain_modulus);
        std::vector<uint32_t> noise;
        sample_query_noise(cols, noise);

        auto public_matrix_prng = create_public_matrix_prng(public_matrix_seed);
        std::vector<uint32_t> public_matrix_row(lwe_dimension);

        for (size_t row = 0; row < cols; row++)
        {
            sample_uniform_u32(public_matrix_prng, lwe_dimension, public_matrix_row.data());

            int64_t inner_product = 0;
            for (size_t j = 0; j < lwe_dimension; j++)
            {
                inner_product += static_cast<int64_t>(public_matrix_row[j]) * secret[j];
            }

            uint32_t query_value = static_cast<uint32_t>(-inner_product);
            query_value += noise[row];
            if (row == target_col)
            {
                query_value += delta;
            }

            query_vector[row] = query_value;
        }
    }
}
