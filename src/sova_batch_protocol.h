#pragma once

#include "pbc.h"
#include "seal/seal.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace sova::pir
{
    struct PackedDatabase
    {
        size_t rows = 0;
        size_t cols = 0;
        size_t padded_rows = 0;
        size_t padded_cols = 0;
        size_t packed_cols = 0;
        std::vector<uint32_t> data;

        [[nodiscard]] bool empty() const { return data.empty(); }
    };

    struct SOVASimplePIRParams
    {
        size_t rows = 0;
        size_t cols = 0;
        size_t lwe_dimension = 0;
        uint64_t record_plain_modulus = 0;
        bool benchmark_randomize_hint_matrix = false;
    };

    struct SOVASimplePIRPublicParams
    {
        SOVASimplePIRParams params;
        seal::prng_seed_type public_matrix_seed = {};
    };

    struct SOVASimplePIRServerState
    {
        std::vector<uint64_t> database;
        std::vector<uint32_t> hint_matrix;
        PackedDatabase packed_database;
    };

    struct BatchBucketLayout
    {
        size_t item_slots = 0;
        size_t items_per_column = 0;
        size_t rows = 0;
        size_t cols = 0;
        size_t record_size_bytes = 0;
    };

    struct SOVABucketPartition
    {
        size_t bucket_begin = 0;
        size_t bucket_count = 0;
        size_t slots_per_bucket = 0;
        size_t num_pages = 0;
        size_t response_page_offset = 0;
    };

    struct SOVAParams
    {
        PBCParams pbc_params;
        size_t lwe_dimension = 1024;
        uint64_t record_plain_modulus = 256;
        size_t record_size_bytes = 256;
        size_t bucket_depth = 0;
        bool benchmark_randomize_hint_matrix = false;
    };

    struct SOVAPublicParams
    {
        SOVAParams params;
        PBCPublicParams pbc_public_params;
        size_t bucket_depth = 0;
        size_t num_pages = 0;
        std::vector<SOVABucketPartition> bucket_partitions;
        std::uint64_t simd_crs_seed = 0;
        std::vector<BatchBucketLayout> bucket_layouts;
        std::vector<SOVASimplePIRPublicParams> bucket_public_params;
    };

    struct SOVAPackedHint
    {
        std::size_t size = 0;
        std::vector<std::uint64_t> words;
    };

    struct SOVAServerState
    {
        PBCServerState pbc_server_state;
        std::vector<SOVASimplePIRServerState> bucket_server_states;
        std::vector<SOVAPackedHint> switched_hint_matrices;
    };

    struct SOVABucketQuery
    {
        size_t bucket_index = 0;
        std::vector<uint32_t> query_vector;
    };

    struct SOVAQueryMessage
    {
        std::vector<SOVABucketQuery> bucket_queries;
        std::vector<seal::seal_byte> evaluation_key;
        std::vector<std::vector<seal::seal_byte>> row_selectors;
        std::vector<seal::seal_byte> galois_keys;
        std::vector<seal::seal_byte> relin_keys;
    };

    struct SOVAClientState
    {
        std::vector<size_t> batch_indices;
        PBCQueryPlan query_plan;
        std::vector<int64_t> query_secret;
    };

    struct SOVAComponentBuffer
    {
        std::vector<uint64_t> data;
    };

    struct SOVAAnswerPrecompState
    {
        bool initialized = false;
        seal::parms_id_type parms_id{};
        std::vector<SOVAComponentBuffer> rotation_prestore;
        std::vector<SOVAComponentBuffer> conversion_diagonal_ntt_pages;
        std::vector<SOVAComponentBuffer> conversion_c1_pages;
        std::vector<SOVAComponentBuffer> row_relin_c1_pages;
        std::vector<SOVAComponentBuffer> row_relin_prestore;
    };

    struct SOVAResponseMessage
    {
        std::vector<seal::Ciphertext> pages;
    };

    struct SOVAAnswerProfile
    {
        double lwes_to_simd_online_b_ms = 0.0;
        double simplepir_ms = 0.0;
        double lwes_to_simd_finalize_ms = 0.0;
        double encrypted_row_selection_ms = 0.0;
        double relinearization_ms = 0.0;
        double modulus_switch_ms = 0.0;
    };

    struct SOVAQueryProfile
    {
        double pbc_ms = 0.0;
        double seed_ms = 0.0;
        double simplepir_ms = 0.0;
        double lwes_to_simd_key_ms = 0.0;
        double row_selector_ms = 0.0;
        double evaluation_keys_ms = 0.0;
        double total_ms = 0.0;
    };

    void SOVADBSetup(
        const std::vector<std::vector<uint8_t>> &database,
        const SOVAParams &params,
        const seal::SEALContext &context,
        SOVAPublicParams &public_params,
        SOVAServerState &server_state);

    void SOVAAnswerPrecompute(
        const SOVAPublicParams &public_params,
        SOVAServerState &server_state,
        const seal::SEALContext &context,
        seal::BatchEncoder &batch_encoder,
        seal::Evaluator &evaluator,
        SOVAAnswerPrecompState &precomp_state);

    void SOVAQuery(
        const SOVAPublicParams &public_params,
        const std::vector<size_t> &batch_indices,
        const seal::SEALContext &context,
        seal::BatchEncoder &batch_encoder,
        seal::KeyGenerator &keygen,
        seal::Encryptor &encryptor,
        SOVAQueryMessage &query,
        SOVAClientState &client_state,
        SOVAQueryProfile *profile = nullptr);

    void SOVAAnswer(
        const SOVAPublicParams &public_params,
        const SOVAServerState &server_state,
        const SOVAAnswerPrecompState &answer_precomp_state,
        const SOVAQueryMessage &query,
        const seal::SEALContext &context,
        seal::BatchEncoder &batch_encoder,
        seal::Encryptor &public_encryptor,
        seal::Evaluator &evaluator,
        SOVAResponseMessage &response,
        SOVAAnswerProfile *profile = nullptr);

    void SOVAExtract(
        const SOVAPublicParams &public_params,
        const SOVAClientState &client_state,
        const SOVAResponseMessage &response,
        seal::BatchEncoder &batch_encoder,
        seal::Decryptor &decryptor,
        std::vector<std::vector<uint8_t>> &records);
}
