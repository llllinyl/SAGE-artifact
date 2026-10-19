#include "sova_batch_protocol.h"

#include "seal/seal.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <limits>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <bit>

using namespace seal;
using namespace sova::pir;

namespace
{
    struct Options
    {
        size_t num_entries = 131072;
        size_t batch_size = 256;
        size_t record_size = 256;
        size_t bucket_depth = 0;
        size_t hash_functions = 3;
        size_t max_attempts = 500;
        double cuckoo_factor = 1.5;
        uint64_t seed = 0x534f5641ULL;
    };

    void print_usage(const char *program)
    {
        std::cout
            << "Usage:\n"
            << "  " << program << " [options]\n"
            << "  " << program << " <num_entries> <batch_size> <record_size> [bucket_depth]\n\n"
            << "Options:\n"
            << "  -n, --num-entries N       number of database records (default: 128)\n"
            << "      --database-mb MiB     derive record count from database size\n"
            << "  -r, --record-size BYTES   bytes per record (default: 64)\n"
            << "  -b, --batch-size L        queried records per batch (default: 8)\n"
            << "  -d, --bucket-depth D      records per SimplePIR column; 0=auto (default: auto)\n"
            << "      --hash-functions H    PBC hash functions (default: 3)\n"
            << "      --cuckoo-factor F     PBC bucket expansion factor (default: 1.5)\n"
            << "      --max-attempts A      PBC assignment attempts (default: 500)\n"
            << "      --seed S              deterministic database seed\n"
            << "  -h, --help                show this message\n\n"
            << "Examples:\n"
            << "  " << program << " --num-entries 2097152 --record-size 256 --batch-size 256 --bucket-depth 8\n"
            << "  " << program << " --database-mb 512 --record-size 256 --batch-size 256 --bucket-depth 0\n";
    }

    bool parse_options(int argc, char **argv, Options &options)
    {
        if (argc > 1 && argv[1][0] != '-')
        {
            if (argc > 5)
            {
                throw std::invalid_argument("too many positional arguments; use --help");
            }
            options.num_entries = std::stoull(argv[1]);
            if (argc > 2) options.batch_size = std::stoull(argv[2]);
            if (argc > 3) options.record_size = std::stoull(argv[3]);
            if (argc > 4) options.bucket_depth = std::stoull(argv[4]);
            return true;
        }

        bool entries_set = false;
        bool database_size_set = false;
        double database_mb = 0.0;
        for (int i = 1; i < argc; i++)
        {
            std::string arg = argv[i];
            if (arg == "-h" || arg == "--help")
            {
                print_usage(argv[0]);
                return false;
            }
            if (i + 1 >= argc)
            {
                throw std::invalid_argument("missing value for " + arg);
            }
            std::string value = argv[++i];
            if (arg == "-n" || arg == "--num-entries")
            {
                options.num_entries = std::stoull(value);
                entries_set = true;
            }
            else if (arg == "--database-mb")
            {
                database_mb = std::stod(value);
                database_size_set = true;
            }
            else if (arg == "-r" || arg == "--record-size")
            {
                options.record_size = std::stoull(value);
            }
            else if (arg == "-b" || arg == "--batch-size")
            {
                options.batch_size = std::stoull(value);
            }
            else if (arg == "-d" || arg == "--bucket-depth")
            {
                options.bucket_depth = std::stoull(value);
            }
            else if (arg == "--hash-functions")
            {
                options.hash_functions = std::stoull(value);
            }
            else if (arg == "--cuckoo-factor")
            {
                options.cuckoo_factor = std::stod(value);
            }
            else if (arg == "--max-attempts")
            {
                options.max_attempts = std::stoull(value);
            }
            else if (arg == "--seed")
            {
                options.seed = std::stoull(value);
            }
            else
            {
                throw std::invalid_argument("unknown option: " + arg);
            }
        }

        if (entries_set && database_size_set)
        {
            throw std::invalid_argument("choose either --num-entries or --database-mb");
        }
        if (database_size_set)
        {
            if (database_mb <= 0.0 || options.record_size == 0)
            {
                throw std::invalid_argument("database and record sizes must be positive");
            }
            long double database_bytes = static_cast<long double>(database_mb) * 1024.0L * 1024.0L;
            options.num_entries = static_cast<size_t>(std::floor(database_bytes / options.record_size));
        }
        return true;
    }

    template <typename Function>
    double time_ms(const std::string &label, Function &&function)
    {
        auto begin = std::chrono::steady_clock::now();
        function();
        auto end = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double, std::milli>(end - begin).count();
        std::cout << std::left << std::setw(28) << label << std::right << std::fixed
                  << std::setprecision(3) << elapsed << " ms\n";
        return elapsed;
    }

    template <typename Serializable>
    size_t bytes(const Serializable &value)
    {
        std::stringstream stream(std::ios::in | std::ios::out | std::ios::binary);
        return static_cast<size_t>(value.save(stream, compr_mode_type::none));
    }
}

int main(int argc, char **argv)
{
    Options options;
    if (!parse_options(argc, argv, options))
    {
        return 0;
    }
    const size_t num_entries = options.num_entries;
    const size_t batch_size = options.batch_size;
    const size_t record_size = options.record_size;
    if (num_entries == 0 || batch_size == 0 || batch_size > num_entries ||
        record_size == 0 || options.hash_functions == 0 || options.cuckoo_factor < 1.0 ||
        options.max_attempts == 0)
    {
        throw std::invalid_argument("invalid benchmark dimensions");
    }
    if (!std::has_single_bit(num_entries) || !std::has_single_bit(batch_size) ||
        !std::has_single_bit(record_size) || batch_size == 1)
    {
        throw std::invalid_argument(
            "num_entries and record_size must be powers of two, and batch_size must be 2^k with k > 0");
    }
    const bool bucket_depth_auto = options.bucket_depth == 0;
    if (bucket_depth_auto)
    {
        options.bucket_depth = std::max<size_t>(
            1, static_cast<size_t>(std::llround(std::sqrt(
                   2.0L * num_entries /
                   (static_cast<long double>(batch_size) * record_size)))));
    }
    const size_t bucket_depth = options.bucket_depth;

    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(4096);
    parms.set_coeff_modulus(CoeffModulus::Create(4096, { 56, 53, 60 }));
    parms.set_plain_modulus(65537);
    SEALContext context(parms);
    if (!context.parameters_set())
    {
        throw std::runtime_error(context.parameter_error_message());
    }

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    Encryptor client_encryptor(context, secret_key);
    Encryptor public_encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    
    constexpr uint64_t split_q1_value = 1ULL << 20;
    constexpr uint64_t split_q2_value = 1ULL << 28;
    constexpr size_t split_q1_bits = 20;
    constexpr size_t split_q2_bits = 28;

    std::mt19937_64 generator(options.seed);
    std::uniform_int_distribution<unsigned int> byte_distribution(0, 255);
    std::vector<std::vector<uint8_t>> database(num_entries, std::vector<uint8_t>(record_size));
    for (auto &record : database)
    {
        for (auto &value : record)
        {
            value = static_cast<uint8_t>(byte_distribution(generator));
        }
    }
    std::vector<size_t> indices(batch_size);
    for (size_t i = 0; i < batch_size; i++)
    {
        indices[i] = (i * num_entries) / batch_size;
    }

    SOVAParams params;
    params.pbc_params.num_entries = num_entries;
    params.pbc_params.batch_size = batch_size;
    params.pbc_params.num_hash_funcs = options.hash_functions;
    params.pbc_params.cuckoo_factor = options.cuckoo_factor;
    params.pbc_params.max_attempts = options.max_attempts;
    params.pbc_params.padding_value = 0;
    params.lwe_dimension = 1024;
    params.record_plain_modulus = 256;
    params.record_size_bytes = record_size;
    params.bucket_depth = bucket_depth;

    SOVAPublicParams public_params;
    SOVAServerState server_state;
    SOVAAnswerPrecompState answer_precomp;
    SOVAQueryMessage query;
    SOVAClientState client_state;
    SOVAResponseMessage response;
    SOVAQueryProfile query_profile;
    SOVAAnswerProfile answer_profile;
    std::vector<std::vector<uint8_t>> extracted;

    std::cout << "SOVA batch PIR (single thread)\n"
              << "entries=" << num_entries << ", batch=" << batch_size
              << ", record=" << record_size << " B, database=" << std::fixed << std::setprecision(3)
              << static_cast<double>(num_entries * record_size) / (1024.0 * 1024.0) << " MiB\n"
              << "PBC: hashes=" << options.hash_functions << ", factor=" << options.cuckoo_factor
              << ", depth=" << bucket_depth << (bucket_depth_auto ? " (auto)" : "")
              << ", seed=" << options.seed << "\n\n";

    time_ms("database setup", [&] {
        SOVADBSetup(database, params, context, public_params, server_state);
    });
    time_ms("database/a-side precompute", [&] {
        SOVAAnswerPrecompute(
            public_params, server_state, context, batch_encoder, evaluator,
            answer_precomp);
    });
    time_ms("online query", [&] {
        SOVAQuery(public_params, indices, context, batch_encoder, keygen, client_encryptor, query, client_state, &query_profile);
    });
    time_ms("online answer", [&] {
        SOVAAnswer(
            public_params, server_state, answer_precomp, query, context,
            batch_encoder, public_encryptor, evaluator, response, &answer_profile);
    });
    time_ms("client extract", [&] {
        SOVAExtract(public_params, client_state, response, batch_encoder, decryptor, extracted);
    });

    std::cout << "\nSOVAQuery breakdown:\n"  << std::fixed << std::setprecision(3)
              << "  PBC:             "       << query_profile.pbc_ms << " ms\n"
              << "  Seed:            "       << query_profile.seed_ms << " ms\n"
              << "  SimplePIR:       "       << query_profile.simplepir_ms << " ms\n"
              << "  LWEsToSIMD:      "       << query_profile.lwes_to_simd_key_ms << " ms\n"
              << "  Row selector:    "       << query_profile.row_selector_ms << " ms\n"
              << "  Evaluation keys: "       << query_profile.evaluation_keys_ms << " ms\n";

    std::cout << "\nSOVAAnswer breakdowm:\n" << std::fixed << std::setprecision(3)
	      << "  SimplePIR:        " << answer_profile.simplepir_ms << " ms\n"
              << "  LWEsToSIMD:       " << answer_profile.lwes_to_simd_online_b_ms + answer_profile.lwes_to_simd_finalize_ms << " ms\n"
              << "  Row selection:    " << answer_profile.encrypted_row_selection_ms + answer_profile.relinearization_ms << " ms\n"
              << "  Modulus switch:   " << answer_profile.modulus_switch_ms << " ms\n";

    bool correct = extracted.size() == indices.size();
    for (size_t i = 0; i < indices.size() && correct; i++)
    {
        correct = extracted[i] == database[indices[i]];
    }
    if (!correct)
    {
        for (size_t i = 0; i < indices.size(); i++)
        {
            for (size_t j = 0; j < record_size; j++)
            {
                if (extracted[i][j] != database[indices[i]][j])
                {
                    std::cout << "first mismatch: query=" << i << ", byte=" << j
                              << ", expected=" << static_cast<unsigned>(database[indices[i]][j])
                              << ", got=" << static_cast<unsigned>(extracted[i][j]) << '\n';
                    i = indices.size();
                    break;
                }
            }
        }
    }

    std::vector<int> rotation_steps;
    for (size_t step = 1; step < params.lwe_dimension; step <<= 1)
    {
        rotation_steps.push_back(static_cast<int>(step));
    }
    auto seeded_galois_keys = keygen.create_galois_keys(rotation_steps);

    Ciphertext evaluation_key;
    evaluation_key.load(context, query.evaluation_key.data(), query.evaluation_key.size());
    Plaintext evaluation_plain;
    decryptor.decrypt(evaluation_key, evaluation_plain);
    auto seeded_evaluation_key = client_encryptor.encrypt_symmetric(evaluation_plain);
    const size_t evaluation_key_bytes = bytes(seeded_evaluation_key);

    size_t row_selector_bytes = 0;
    for (const auto &selector : query.row_selectors)
    {
        Ciphertext selector_cipher;
        selector_cipher.load(context, selector.data(), selector.size());
        Plaintext selector_plain;
        decryptor.decrypt(selector_cipher, selector_plain);
        auto seeded_selector = client_encryptor.encrypt_symmetric(selector_plain);
        row_selector_bytes += bytes(seeded_selector);
    }

    size_t simplepir_query_bytes = 0;
    for (const auto &bucket : query.bucket_queries)
    {
        simplepir_query_bytes += bucket.query_vector.size() * sizeof(uint32_t);
    }
    const size_t galois_key_bytes = bytes(seeded_galois_keys);
    size_t relin_key_bytes = 0;
    if (!query.relin_keys.empty())
    {
        auto seeded_relin_keys = keygen.create_relin_keys();
        relin_key_bytes = bytes(seeded_relin_keys);
    }
    const size_t query_bytes = simplepir_query_bytes + evaluation_key_bytes +
        row_selector_bytes + galois_key_bytes + relin_key_bytes;
    size_t response_bytes = 0;
    size_t split_response_bytes = 0;
    const Modulus split_q1(split_q1_value);
    const Modulus split_q2(split_q2_value);
    for (const auto &page : response.pages)
    {
        response_bytes += bytes(page);
        Ciphertext split_page = page;
        evaluator.split_mod_switch_inplace(split_page, split_q1, split_q2);
        const size_t degree = split_page.poly_modulus_degree();
        split_response_bytes +=
            (degree * split_q1_bits + 7) / 8 +
            (degree * split_q2_bits + 7) / 8;
    }

    std::cout << "\nQuery sizes (KiB, /1024; raw vectors + uncompressed SEAL serialization):\n"
              << std::fixed << std::setprecision(2)
              << "  SimplePIR vectors: " << static_cast<double>(simplepir_query_bytes) / 1024.0 << '\n'
              << "  evaluation key [seeded-est]: " << static_cast<double>(evaluation_key_bytes) / 1024.0 << '\n'
              << "  row selectors [seeded-est]: " << static_cast<double>(row_selector_bytes) / 1024.0 << '\n'
              << "  Galois keys [seeded-est]: " << static_cast<double>(galois_key_bytes) / 1024.0 << '\n'
              << "  relin keys [seeded-est]: " << static_cast<double>(relin_key_bytes) / 1024.0 << '\n'
              << "query total [seeded-est]: " << static_cast<double>(query_bytes) / 1024.0 << " KiB\n"
              << "response [full/split]: " << static_cast<double>(response_bytes) / 1024.0
              << " / " << static_cast<double>(split_response_bytes) / 1024.0
              << " KiB\n"
              << "correctness: " << (correct ? "PASS" : "FAIL") << '\n';

    return correct ? 0 : 1;
}

