#pragma once

#include "pbc.h"
#include "seal/seal.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace sage::pir
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

    struct SAGESimplePIRParams
    {
        size_t rows = 0;
        size_t cols = 0;
        size_t lwe_dimension = 0;
        uint64_t record_plain_modulus = 0;
        bool benchmark_randomize_hint_matrix = false;
    };

    struct SAGESimplePIRPublicParams
    {
        SAGESimplePIRParams params;
        seal::prng_seed_type public_matrix_seed = {};
    };

    struct SAGESimplePIRServerState
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

    struct SAGEBucketPartition
    {
        size_t bucket_begin = 0;
        size_t bucket_count = 0;
        size_t slots_per_bucket = 0;
        size_t num_pages = 0;
        size_t response_page_offset = 0;
    };

    struct SAGEParams
    {
        PBCParams pbc_params;
        size_t lwe_dimension = 1024;
        uint64_t record_plain_modulus = 256;
        size_t record_size_bytes = 256;
        size_t bucket_depth = 0;
        bool benchmark_randomize_hint_matrix = false;
    };

    struct SAGEPublicParams
    {
        SAGEParams params;
        PBCPublicParams pbc_public_params;
        size_t bucket_depth = 0;
        size_t num_pages = 0;
        std::vector<SAGEBucketPartition> bucket_partitions;
        std::uint64_t simd_crs_seed = 0;
        std::vector<BatchBucketLayout> bucket_layouts;
        std::vector<SAGESimplePIRPublicParams> bucket_public_params;
    };

    struct SAGEPackedHint
    {
        std::size_t size = 0;
        std::vector<std::uint64_t> words;
    };

    struct SAGEServerState
    {
        PBCServerState pbc_server_state;
        std::vector<SAGESimplePIRServerState> bucket_server_states;
        std::vector<SAGEPackedHint> switched_hint_matrices;
    };

    struct SAGEBucketQuery
    {
        size_t bucket_index = 0;
        std::vector<uint32_t> query_vector;
    };

    struct SAGEQueryMessage
    {
        std::vector<SAGEBucketQuery> bucket_queries;
        std::vector<seal::seal_byte> evaluation_key;
        std::vector<std::vector<seal::seal_byte>> row_selectors;
        std::vector<seal::seal_byte> galois_keys;
        std::vector<seal::seal_byte> relin_keys;
    };

    struct SAGEClientState
    {
        std::vector<size_t> batch_indices;
        PBCQueryPlan query_plan;
        std::vector<int64_t> query_secret;
    };

    struct SAGEComponentBuffer
    {
        std::vector<uint64_t> data;
    };

    struct SAGEAnswerPrecompState
    {
        bool initialized = false;
        seal::parms_id_type parms_id{};
        std::vector<SAGEComponentBuffer> rotation_prestore;
        std::vector<SAGEComponentBuffer> conversion_diagonal_ntt_pages;
        std::vector<SAGEComponentBuffer> conversion_c1_pages;
        std::vector<SAGEComponentBuffer> row_relin_c1_pages;
        std::vector<SAGEComponentBuffer> row_relin_prestore;
    };

    struct SAGEResponseMessage
    {
        std::vector<seal::Ciphertext> pages;
    };

    struct SAGEAnswerProfile
    {
        double lwes_to_simd_online_b_ms = 0.0;
        double simplepir_ms = 0.0;
        double lwes_to_simd_finalize_ms = 0.0;
        double encrypted_row_selection_ms = 0.0;
        double relinearization_ms = 0.0;
        double modulus_switch_ms = 0.0;
    };

    struct SAGEQueryProfile
    {
        double pbc_ms = 0.0;
        double seed_ms = 0.0;
        double simplepir_ms = 0.0;
        double lwes_to_simd_key_ms = 0.0;
        double row_selector_ms = 0.0;
        double evaluation_keys_ms = 0.0;
        double total_ms = 0.0;
    };

    void SAGEDBSetup(
        const std::vector<std::vector<uint8_t>> &database,
        const SAGEParams &params,
        const seal::SEALContext &context,
        SAGEPublicParams &public_params,
        SAGEServerState &server_state);

    void SAGEAnswerPrecompute(
        const SAGEPublicParams &public_params,
        SAGEServerState &server_state,
        const seal::SEALContext &context,
        seal::BatchEncoder &batch_encoder,
        seal::Evaluator &evaluator,
        SAGEAnswerPrecompState &precomp_state);

    void SAGEQuery(
        const SAGEPublicParams &public_params,
        const std::vector<size_t> &batch_indices,
        const seal::SEALContext &context,
        seal::BatchEncoder &batch_encoder,
        seal::KeyGenerator &keygen,
        seal::Encryptor &encryptor,
        SAGEQueryMessage &query,
        SAGEClientState &client_state,
        SAGEQueryProfile *profile = nullptr);

    void SAGEAnswer(
        const SAGEPublicParams &public_params,
        const SAGEServerState &server_state,
        const SAGEAnswerPrecompState &answer_precomp_state,
        const SAGEQueryMessage &query,
        const seal::SEALContext &context,
        seal::BatchEncoder &batch_encoder,
        seal::Encryptor &public_encryptor,
        seal::Evaluator &evaluator,
        SAGEResponseMessage &response,
        SAGEAnswerProfile *profile = nullptr);

    void SAGEExtract(
        const SAGEPublicParams &public_params,
        const SAGEClientState &client_state,
        const SAGEResponseMessage &response,
        seal::BatchEncoder &batch_encoder,
        seal::Decryptor &decryptor,
        std::vector<std::vector<uint8_t>> &records);
}
