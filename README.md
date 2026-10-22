
## Build

```bash
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DSEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=OFF -DSEAL_USE_INTEL_HEXL=ON
make
```

## End-to-end test

```bash
./build/bin/test_sage_batch
./build/bin/test_sage_batch --num-entries 256 --record-size 256 --batch-size 8 --bucket-depth 2
./build/bin/test_sage_batch --database-mb 512 --record-size 256 --batch-size 256 --bucket-depth 0
```

Run `test_sage_batch --help` for all PBC and reproducibility options. The legacy
positional form `num_entries batch_size record_size_bytes [bucket_depth]` remains
available. The benchmark uses one process and one thread and reports setup,
preprocessing, query, answer, extraction, communication, noise budget, and
end-to-end correctness.
