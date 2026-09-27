
BenchmarkDotNet v0.15.8, Linux Ubuntu 24.04.5 LTS (Noble Numbat)
INTEL XEON PLATINUM 8573C 2.30GHz, 1 CPU, 4 logical and 2 physical cores
.NET SDK 10.0.401
  [Host]    : .NET 10.0.12 (10.0.12, 10.0.1226.42308), X64 RyuJIT x86-64-v4
  .NET 10.0 : .NET 10.0.12 (10.0.12, 10.0.1226.42308), X64 RyuJIT x86-64-v4
  .NET 8.0  : .NET 8.0.31 (8.0.31, 8.0.3126.42015), X64 RyuJIT x86-64-v4
  .NET 9.0  : .NET 9.0.20 (9.0.20, 9.0.2026.41315), X64 RyuJIT x86-64-v4


 Method                                                       | Job       | Runtime   | Mean              | Error          | StdDev         | Ratio | Gen0   | Allocated | Alloc Ratio |
------------------------------------------------------------- |---------- |---------- |------------------:|---------------:|---------------:|------:|-------:|----------:|------------:|
 'AES-GCM 256-bit Encrypt (Span, Zero-Alloc)'                 | .NET 10.0 | .NET 10.0 |       2,757.57 ns |       7.166 ns |       6.352 ns |  0.99 |      - |      64 B |        1.00 |
 'AES-GCM 256-bit Encrypt (Span, Zero-Alloc)'                 | .NET 8.0  | .NET 8.0  |       2,772.88 ns |       6.097 ns |       5.405 ns |  1.00 |      - |      64 B |        1.00 |
 'AES-GCM 256-bit Encrypt (Span, Zero-Alloc)'                 | .NET 9.0  | .NET 9.0  |       2,771.79 ns |       5.137 ns |       4.290 ns |  1.00 |      - |      64 B |        1.00 |
                                                              |           |           |                   |                |                |       |        |           |             |
 'AES-GCM 256-bit Decrypt (Span, Zero-Alloc)'                 | .NET 10.0 | .NET 10.0 |       1,894.96 ns |       3.979 ns |       3.323 ns |  1.00 |      - |      32 B |        0.50 |
 'AES-GCM 256-bit Decrypt (Span, Zero-Alloc)'                 | .NET 8.0  | .NET 8.0  |       1,894.39 ns |       4.399 ns |       3.673 ns |  1.00 |      - |      64 B |        1.00 |
 'AES-GCM 256-bit Decrypt (Span, Zero-Alloc)'                 | .NET 9.0  | .NET 9.0  |       1,910.18 ns |       7.088 ns |       6.284 ns |  1.01 |      - |      64 B |        1.00 |
                                                              |           |           |                   |                |                |       |        |           |             |
 'AES-GCM Parallel Concurrent Throughput (100 ops)'           | .NET 10.0 | .NET 10.0 |     153,162.65 ns |   1,435.283 ns |   1,342.564 ns |  1.02 |      - |    8630 B |        1.00 |
 'AES-GCM Parallel Concurrent Throughput (100 ops)'           | .NET 8.0  | .NET 8.0  |     149,944.70 ns |   1,692.403 ns |   1,583.075 ns |  1.00 |      - |    8623 B |        1.00 |
 'AES-GCM Parallel Concurrent Throughput (100 ops)'           | .NET 9.0  | .NET 9.0  |     150,813.64 ns |   1,673.615 ns |   1,565.501 ns |  1.01 |      - |    8626 B |        1.00 |
                                                              |           |           |                   |                |                |       |        |           |             |
 'PBKDF2-SHA512 Password Hash (10k iters)'                    | .NET 10.0 | .NET 10.0 |   5,727,896.91 ns |  11,409.037 ns |  10,672.020 ns |  1.00 |      - |     464 B |        0.92 |
 'PBKDF2-SHA512 Password Hash (10k iters)'                    | .NET 8.0  | .NET 8.0  |   5,719,028.73 ns |   6,628.531 ns |   5,175.121 ns |  1.00 |      - |     504 B |        1.00 |
 'PBKDF2-SHA512 Password Hash (10k iters)'                    | .NET 9.0  | .NET 9.0  |   5,723,626.99 ns |   8,573.632 ns |   7,159.371 ns |  1.00 |      - |     464 B |        0.92 |
                                                              |           |           |                   |                |                |       |        |           |             |
 'PBKDF2-SHA512 Password Hash (600K iters — PRODUCTION COST)' | .NET 10.0 | .NET 10.0 | 342,720,828.31 ns | 645,598.852 ns | 539,104.281 ns |  1.00 |      - |     504 B |        1.00 |
 'PBKDF2-SHA512 Password Hash (600K iters — PRODUCTION COST)' | .NET 8.0  | .NET 8.0  | 342,614,953.46 ns | 634,448.802 ns | 529,793.484 ns |  1.00 |      - |     504 B |        1.00 |
 'PBKDF2-SHA512 Password Hash (600K iters — PRODUCTION COST)' | .NET 9.0  | .NET 9.0  | 342,248,278.64 ns | 389,330.958 ns | 345,131.754 ns |  1.00 |      - |     504 B |        1.00 |
                                                              |           |           |                   |                |                |       |        |           |             |
 'LegacyPbkdf2 Password Hash (Fast Config)'                   | .NET 10.0 | .NET 10.0 |  40,204,747.47 ns | 289,743.058 ns | 241,948.576 ns |  1.00 |      - |     416 B |        0.91 |
 'LegacyPbkdf2 Password Hash (Fast Config)'                   | .NET 8.0  | .NET 8.0  |  40,064,867.49 ns | 121,149.202 ns |  94,585.328 ns |  1.00 |      - |     456 B |        1.00 |
 'LegacyPbkdf2 Password Hash (Fast Config)'                   | .NET 9.0  | .NET 9.0  |  40,175,666.29 ns | 157,403.567 ns | 139,534.162 ns |  1.00 |      - |     416 B |        0.91 |
                                                              |           |           |                   |                |                |       |        |           |             |
 'CompositePasswordHasher Verify & Rehash Check'              | .NET 10.0 | .NET 10.0 |   5,721,806.34 ns |   7,607.984 ns |   6,744.279 ns |  1.00 |      - |     464 B |        1.00 |
 'CompositePasswordHasher Verify & Rehash Check'              | .NET 8.0  | .NET 8.0  |   5,721,481.61 ns |  12,819.822 ns |  11,991.669 ns |  1.00 |      - |     464 B |        1.00 |
 'CompositePasswordHasher Verify & Rehash Check'              | .NET 9.0  | .NET 9.0  |   5,725,853.63 ns |   8,242.010 ns |   7,709.581 ns |  1.00 |      - |     464 B |        1.00 |
                                                              |           |           |                   |                |                |       |        |           |             |
 'SecurityEnvelope Serialize (Span, Zero-Alloc)'              | .NET 10.0 | .NET 10.0 |          25.78 ns |       0.029 ns |       0.024 ns |  0.90 |      - |         - |          NA |
 'SecurityEnvelope Serialize (Span, Zero-Alloc)'              | .NET 8.0  | .NET 8.0  |          28.69 ns |       0.031 ns |       0.026 ns |  1.00 |      - |         - |          NA |
 'SecurityEnvelope Serialize (Span, Zero-Alloc)'              | .NET 9.0  | .NET 9.0  |          26.92 ns |       0.052 ns |       0.040 ns |  0.94 |      - |         - |          NA |
                                                              |           |           |                   |                |                |       |        |           |             |
 'SecurityEnvelope Deserialize (Span)'                        | .NET 10.0 | .NET 10.0 |          75.36 ns |       0.226 ns |       0.211 ns |  0.87 | 0.0056 |     472 B |        1.00 |
 'SecurityEnvelope Deserialize (Span)'                        | .NET 8.0  | .NET 8.0  |          86.31 ns |       0.830 ns |       0.693 ns |  1.00 | 0.0056 |     472 B |        1.00 |
 'SecurityEnvelope Deserialize (Span)'                        | .NET 9.0  | .NET 9.0  |          85.24 ns |       0.477 ns |       0.423 ns |  0.99 | 0.0056 |     472 B |        1.00 |
                                                              |           |           |                   |                |                |       |        |           |             |
 'ConstantTime FixedTimeEquals (32 bytes)'                    | .NET 10.0 | .NET 10.0 |         151.33 ns |       0.892 ns |       0.835 ns |  0.88 |      - |         - |          NA |
 'ConstantTime FixedTimeEquals (32 bytes)'                    | .NET 8.0  | .NET 8.0  |         171.37 ns |       1.388 ns |       1.230 ns |  1.00 |      - |         - |          NA |
 'ConstantTime FixedTimeEquals (32 bytes)'                    | .NET 9.0  | .NET 9.0  |         141.15 ns |       0.338 ns |       0.316 ns |  0.82 |      - |         - |          NA |
                                                              |           |           |                   |                |                |       |        |           |             |
 'Token Generation (URL-Safe 32 bytes)'                       | .NET 10.0 | .NET 10.0 |         945.98 ns |       3.580 ns |       3.349 ns |  1.00 | 0.0038 |     388 B |        1.00 |
 'Token Generation (URL-Safe 32 bytes)'                       | .NET 8.0  | .NET 8.0  |         947.53 ns |       5.141 ns |       4.558 ns |  1.00 | 0.0038 |     388 B |        1.00 |
 'Token Generation (URL-Safe 32 bytes)'                       | .NET 9.0  | .NET 9.0  |         943.36 ns |       2.135 ns |       1.997 ns |  1.00 | 0.0038 |     388 B |        1.00 |
                                                              |           |           |                   |                |                |       |        |           |             |
 'Token Hash (SHA-256)'                                       | .NET 10.0 | .NET 10.0 |         613.10 ns |       1.812 ns |       1.513 ns |  0.71 | 0.0019 |     184 B |        1.00 |
 'Token Hash (SHA-256)'                                       | .NET 8.0  | .NET 8.0  |         859.36 ns |       1.202 ns |       0.938 ns |  1.00 | 0.0019 |     184 B |        1.00 |
 'Token Hash (SHA-256)'                                       | .NET 9.0  | .NET 9.0  |         909.85 ns |       1.490 ns |       1.245 ns |  1.06 | 0.0019 |     184 B |        1.00 |
                                                              |           |           |                   |                |                |       |        |           |             |
 'SecretBuffer Allocate & Dispose (ZeroMemory)'               | .NET 10.0 | .NET 10.0 |          63.37 ns |       0.224 ns |       0.209 ns |  0.93 | 0.0004 |      32 B |        1.00 |
 'SecretBuffer Allocate & Dispose (ZeroMemory)'               | .NET 8.0  | .NET 8.0  |          68.33 ns |       0.366 ns |       0.286 ns |  1.00 | 0.0004 |      32 B |        1.00 |
 'SecretBuffer Allocate & Dispose (ZeroMemory)'               | .NET 9.0  | .NET 9.0  |          60.97 ns |       0.264 ns |       0.247 ns |  0.89 | 0.0004 |      32 B |        1.00 |
