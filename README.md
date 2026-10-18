SOVA is a single-threaded prototype of batch hintless single-server PIR. It combines
bucketed SimplePIR with an LWE-to-SIMD conversion and one SIMD selection layer.

The response encryption parameters are built from the SPIRIT baseline:

- BGV polynomial degree: `2048`
- coefficient-modulus bit sizes: `{56, 56, 60}`
- batching plaintext modulus: `65537`
- LWE dimension: `1024`

The first 56-bit data prime is the SPIRIT response level. SOVA adds one 56-bit
data prime for its single encrypted-selector multiplication and drops that prime
before returning the response; the 60-bit prime remains the key-switching prime.

The per-query SIMD evaluation-key ciphertext, row selectors, Galois keys, and
relinearization key are all sent online and counted in query communication. Every
fresh symmetric RLWE ciphertext and key-switching-key ciphertext uses SEAL's seeded
serialization: only the message-bearing component is transmitted, while the uniform
`a`-component is regenerated from its PRG seed by the server.

The two 56-bit data primes are noise capacity rather than two consumed multiplicative
levels. `LWEsToSIMD` is linear and consumes no level. The encrypted selector product is
performed over both data primes, after which the second prime is dropped to return a
single-56-bit response. A one-prime query cannot in general be raised to this two-prime
ciphertext without additional conversion material; seeded full-level encryption is the
standard compact representation used here.
Database-dependent diagonal plaintexts are encoded and transformed to NTT form in
`SOVAAnswerPrecompute`; all evaluation-key rotations and encrypted hint products are
moved to `SOVAAnswerQueryPrecompute`. The timed answer path contains no external
product and performs only SimplePIR products, selector/plaintext products, and
page-wise additions.

## Build

```bash
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DSEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=OFF -DSEAL_USE_INTEL_HEXL=ON
make
```

## End-to-end test

```bash
./build/bin/test_sova_batch
./build/bin/test_sova_batch --num-entries 256 --record-size 256 --batch-size 8 --bucket-depth 2
./build/bin/test_sova_batch --database-mb 512 --record-size 256 --batch-size 256 --bucket-depth 0
```

Run `test_sova_batch --help` for all PBC and reproducibility options. The legacy
positional form `num_entries batch_size record_size_bytes [bucket_depth]` remains
available. The benchmark uses one process and one thread and reports setup,
preprocessing, query, answer, extraction, communication, noise budget, and
end-to-end correctness.
