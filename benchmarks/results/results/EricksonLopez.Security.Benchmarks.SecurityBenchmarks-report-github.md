```

BenchmarkDotNet v0.15.8, Linux Ubuntu 24.04.5 LTS (Noble Numbat)
AMD EPYC 7763 2.45GHz, 1 CPU, 4 logical and 2 physical cores
.NET SDK 10.0.401
  [Host]    : .NET 10.0.12 (10.0.12, 10.0.1226.42308), X64 RyuJIT x86-64-v3
  .NET 10.0 : .NET 10.0.12 (10.0.12, 10.0.1226.42308), X64 RyuJIT x86-64-v3
  .NET 8.0  : .NET 8.0.31 (8.0.31, 8.0.3126.42015), X64 RyuJIT x86-64-v3
  .NET 9.0  : .NET 9.0.20 (9.0.20, 9.0.2026.41315), X64 RyuJIT x86-64-v3


```
| Method                                                       | Job       | Runtime   | Mean              | Error          | StdDev         | Ratio | Gen0   | Allocated | Alloc Ratio |
|------------------------------------------------------------- |---------- |---------- |------------------:|---------------:|---------------:|------:|-------:|----------:|------------:|
| &#39;AES-GCM 256-bit Encrypt (Span, Zero-Alloc)&#39;                 | .NET 10.0 | .NET 10.0 |       3,560.21 ns |      11.837 ns |      11.073 ns |  0.91 | 0.0038 |      64 B |        1.00 |
| &#39;AES-GCM 256-bit Encrypt (Span, Zero-Alloc)&#39;                 | .NET 8.0  | .NET 8.0  |       3,891.72 ns |       2.596 ns |       2.168 ns |  1.00 |      - |      64 B |        1.00 |
| &#39;AES-GCM 256-bit Encrypt (Span, Zero-Alloc)&#39;                 | .NET 9.0  | .NET 9.0  |       3,908.26 ns |      12.231 ns |      10.843 ns |  1.00 |      - |      64 B |        1.00 |
|                                                              |           |           |                   |                |                |       |        |           |             |
| &#39;AES-GCM 256-bit Decrypt (Span, Zero-Alloc)&#39;                 | .NET 10.0 | .NET 10.0 |       2,233.85 ns |       4.476 ns |       3.968 ns |  0.98 |      - |      32 B |        0.50 |
| &#39;AES-GCM 256-bit Decrypt (Span, Zero-Alloc)&#39;                 | .NET 8.0  | .NET 8.0  |       2,289.99 ns |       4.069 ns |       3.607 ns |  1.00 | 0.0038 |      64 B |        1.00 |
| &#39;AES-GCM 256-bit Decrypt (Span, Zero-Alloc)&#39;                 | .NET 9.0  | .NET 9.0  |       2,570.01 ns |       3.384 ns |       2.999 ns |  1.12 | 0.0038 |      64 B |        1.00 |
|                                                              |           |           |                   |                |                |       |        |           |             |
| &#39;AES-GCM Parallel Concurrent Throughput (100 ops)&#39;           | .NET 10.0 | .NET 10.0 |     193,646.22 ns |   1,976.089 ns |   1,751.752 ns |  0.99 | 0.4883 |    8630 B |        1.00 |
| &#39;AES-GCM Parallel Concurrent Throughput (100 ops)&#39;           | .NET 8.0  | .NET 8.0  |     195,818.63 ns |   1,043.527 ns |     871.392 ns |  1.00 | 0.4883 |    8629 B |        1.00 |
| &#39;AES-GCM Parallel Concurrent Throughput (100 ops)&#39;           | .NET 9.0  | .NET 9.0  |     195,895.83 ns |   1,657.568 ns |   1,469.391 ns |  1.00 | 0.4883 |    8626 B |        1.00 |
|                                                              |           |           |                   |                |                |       |        |           |             |
| &#39;PBKDF2-SHA512 Password Hash (10k iters)&#39;                    | .NET 10.0 | .NET 10.0 |   6,734,630.11 ns |  11,018.713 ns |   9,201.124 ns |  0.99 |      - |     464 B |        0.92 |
| &#39;PBKDF2-SHA512 Password Hash (10k iters)&#39;                    | .NET 8.0  | .NET 8.0  |   6,784,156.46 ns |  13,645.499 ns |  12,096.379 ns |  1.00 |      - |     504 B |        1.00 |
| &#39;PBKDF2-SHA512 Password Hash (10k iters)&#39;                    | .NET 9.0  | .NET 9.0  |   6,793,666.81 ns |  10,783.343 ns |  10,086.745 ns |  1.00 |      - |     464 B |        0.92 |
|                                                              |           |           |                   |                |                |       |        |           |             |
| &#39;PBKDF2-SHA512 Password Hash (600K iters — PRODUCTION COST)&#39; | .NET 10.0 | .NET 10.0 | 405,122,262.43 ns | 741,738.129 ns | 657,531.532 ns |  1.00 |      - |     504 B |        1.00 |
| &#39;PBKDF2-SHA512 Password Hash (600K iters — PRODUCTION COST)&#39; | .NET 8.0  | .NET 8.0  | 405,820,266.62 ns | 691,280.117 ns | 577,250.206 ns |  1.00 |      - |     504 B |        1.00 |
| &#39;PBKDF2-SHA512 Password Hash (600K iters — PRODUCTION COST)&#39; | .NET 9.0  | .NET 9.0  | 405,294,660.80 ns | 516,188.232 ns | 482,842.793 ns |  1.00 |      - |     504 B |        1.00 |
|                                                              |           |           |                   |                |                |       |        |           |             |
| &#39;LegacyPbkdf2 Password Hash (Fast Config)&#39;                   | .NET 10.0 | .NET 10.0 |  47,127,059.98 ns | 130,072.497 ns | 108,616.426 ns |  1.00 |      - |     416 B |        0.91 |
| &#39;LegacyPbkdf2 Password Hash (Fast Config)&#39;                   | .NET 8.0  | .NET 8.0  |  47,027,026.94 ns |  56,050.338 ns |  46,804.571 ns |  1.00 |      - |     456 B |        1.00 |
| &#39;LegacyPbkdf2 Password Hash (Fast Config)&#39;                   | .NET 9.0  | .NET 9.0  |  47,359,988.79 ns |  36,542.585 ns |  32,394.050 ns |  1.01 |      - |     416 B |        0.91 |
|                                                              |           |           |                   |                |                |       |        |           |             |
| &#39;CompositePasswordHasher Verify &amp; Rehash Check&#39;              | .NET 10.0 | .NET 10.0 |   6,737,228.51 ns |  18,217.343 ns |  14,222.903 ns |  0.99 |      - |     464 B |        1.00 |
| &#39;CompositePasswordHasher Verify &amp; Rehash Check&#39;              | .NET 8.0  | .NET 8.0  |   6,782,333.12 ns |   6,422.052 ns |   5,362.704 ns |  1.00 |      - |     464 B |        1.00 |
| &#39;CompositePasswordHasher Verify &amp; Rehash Check&#39;              | .NET 9.0  | .NET 9.0  |   6,842,881.23 ns |  91,876.563 ns |  85,941.394 ns |  1.01 |      - |     464 B |        1.00 |
|                                                              |           |           |                   |                |                |       |        |           |             |
| &#39;SecurityEnvelope Serialize (Span, Zero-Alloc)&#39;              | .NET 10.0 | .NET 10.0 |          38.68 ns |       0.078 ns |       0.069 ns |  1.02 |      - |         - |          NA |
| &#39;SecurityEnvelope Serialize (Span, Zero-Alloc)&#39;              | .NET 8.0  | .NET 8.0  |          37.93 ns |       0.034 ns |       0.030 ns |  1.00 |      - |         - |          NA |
| &#39;SecurityEnvelope Serialize (Span, Zero-Alloc)&#39;              | .NET 9.0  | .NET 9.0  |          37.93 ns |       0.035 ns |       0.033 ns |  1.00 |      - |         - |          NA |
|                                                              |           |           |                   |                |                |       |        |           |             |
| &#39;SecurityEnvelope Deserialize (Span)&#39;                        | .NET 10.0 | .NET 10.0 |          97.84 ns |       0.346 ns |       0.307 ns |  0.90 | 0.0281 |     472 B |        1.00 |
| &#39;SecurityEnvelope Deserialize (Span)&#39;                        | .NET 8.0  | .NET 8.0  |         109.14 ns |       0.763 ns |       0.714 ns |  1.00 | 0.0281 |     472 B |        1.00 |
| &#39;SecurityEnvelope Deserialize (Span)&#39;                        | .NET 9.0  | .NET 9.0  |         101.77 ns |       0.627 ns |       0.586 ns |  0.93 | 0.0281 |     472 B |        1.00 |
|                                                              |           |           |                   |                |                |       |        |           |             |
| &#39;ConstantTime FixedTimeEquals (32 bytes)&#39;                    | .NET 10.0 | .NET 10.0 |         131.13 ns |       0.064 ns |       0.050 ns |  1.00 |      - |         - |          NA |
| &#39;ConstantTime FixedTimeEquals (32 bytes)&#39;                    | .NET 8.0  | .NET 8.0  |         131.76 ns |       0.101 ns |       0.085 ns |  1.00 |      - |         - |          NA |
| &#39;ConstantTime FixedTimeEquals (32 bytes)&#39;                    | .NET 9.0  | .NET 9.0  |         132.19 ns |       0.144 ns |       0.121 ns |  1.00 |      - |         - |          NA |
|                                                              |           |           |                   |                |                |       |        |           |             |
| &#39;Token Generation (URL-Safe 32 bytes)&#39;                       | .NET 10.0 | .NET 10.0 |       1,267.40 ns |       1.204 ns |       0.940 ns |  0.93 | 0.0229 |     388 B |        1.00 |
| &#39;Token Generation (URL-Safe 32 bytes)&#39;                       | .NET 8.0  | .NET 8.0  |       1,356.06 ns |       5.298 ns |       4.696 ns |  1.00 | 0.0229 |     388 B |        1.00 |
| &#39;Token Generation (URL-Safe 32 bytes)&#39;                       | .NET 9.0  | .NET 9.0  |       1,411.66 ns |       3.609 ns |       3.199 ns |  1.04 | 0.0229 |     389 B |        1.00 |
|                                                              |           |           |                   |                |                |       |        |           |             |
| &#39;Token Hash (SHA-256)&#39;                                       | .NET 10.0 | .NET 10.0 |         627.06 ns |       1.829 ns |       1.621 ns |  0.61 | 0.0105 |     184 B |        1.00 |
| &#39;Token Hash (SHA-256)&#39;                                       | .NET 8.0  | .NET 8.0  |       1,019.70 ns |       1.725 ns |       1.529 ns |  1.00 | 0.0095 |     184 B |        1.00 |
| &#39;Token Hash (SHA-256)&#39;                                       | .NET 9.0  | .NET 9.0  |       1,036.51 ns |       2.448 ns |       2.170 ns |  1.02 | 0.0095 |     184 B |        1.00 |
|                                                              |           |           |                   |                |                |       |        |           |             |
| &#39;SecretBuffer Allocate &amp; Dispose (ZeroMemory)&#39;               | .NET 10.0 | .NET 10.0 |          71.30 ns |       0.158 ns |       0.123 ns |  0.84 | 0.0019 |      32 B |        1.00 |
| &#39;SecretBuffer Allocate &amp; Dispose (ZeroMemory)&#39;               | .NET 8.0  | .NET 8.0  |          84.98 ns |       0.129 ns |       0.115 ns |  1.00 | 0.0019 |      32 B |        1.00 |
| &#39;SecretBuffer Allocate &amp; Dispose (ZeroMemory)&#39;               | .NET 9.0  | .NET 9.0  |          69.66 ns |       0.199 ns |       0.176 ns |  0.82 | 0.0019 |      32 B |        1.00 |
