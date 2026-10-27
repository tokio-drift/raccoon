# RACCOON Performance & Memory Verification

This document records the performance benchmarks (PLAN 13.2) and memory budget verification (PLAN 13.3) for RACCOON against synthetic multi-flow PCAPs generated via `scripts/gen_big_pcap.go`.

---

## 1. Environment & Setup

- **OS / Kernel**: Linux (Ubuntu 24.04 LTS / 6.6.137+ x86_64)
- **CPU**: 13th Gen Intel(R) Core(TM) i7-13650HX (20 threads)
- **Memory**: 32 GB RAM
- **Go Toolchain**: `go version go1.22.12 linux/amd64`
- **Compiler Flags**: Default (`CGO_ENABLED=0`)
- **Synthetic Test Captures**:
  - `testdata/big/big_100mb.pcap`: 104,865,317 bytes (~100 MB), 20,323 streams, 245,007 packets.
  - `testdata/big/big_500mb.pcap`: 524,296,454 bytes (~500 MB), 101,564 streams, 1,224,548 packets.
  - Protocols: HTTP (GET, chunked, static assets), FTP (commands + transfers), DNS queries and responses over UDP.
  - Embedded artifacts: PNG (`6c03281...`), JPEG (`bae8839...`), PDF (`3b7faaf...`), ZIP (`83a5d48...`).
  - Network anomalies: TCP retransmissions and out-of-order packet segments.

---

## 2. 100 MB Analysis Benchmark (PLAN 13.2)

### Target
- **Timeline ready in < 20 s.**

### Results
- **Command**: `raccoon analyze testdata/big/big_100mb.pcap --report json --offline`
- **Pipeline Analysis Duration**: **3.107 s**
- **Process Wall-Clock Time**: **3.540 s**
- **Benchmark Run (`Benchmark100MB`)**: **2.871 s/op** (9,560,422,072 B/op, 6,463,125 allocs/op)
- **Verdict**: **PASS** (3.11 s is ~6.4x faster than the 20 s threshold).

### Top CPU Consumers (`pprof` -top)

```
Showing nodes accounting for 6.25s, 81.06% of 7.71s total
Dropped 466 nodes (cum <= 0.04s)
      flat  flat%   sum%        cum   cum%
     0.95s 12.32% 12.32%      0.95s 12.32%  runtime.memclrNoHeapPointers
     0.85s 11.02% 23.35%      0.85s 11.02%  internal/runtime/syscall/linux.Syscall6
     0.55s  7.13% 30.48%      1.10s 14.27%  runtime.scanObjectsSmall
     0.49s  6.36% 36.84%      0.81s 10.51%  runtime.tryDeferToSpanScan
     0.30s  3.89% 40.73%      0.44s  5.71%  runtime.scanblock
     0.29s  3.76% 44.49%      0.30s  3.89%  github.com/tokio-drift/raccoon/internal/carve.(*Matcher).Scan
     0.21s  2.72% 47.21%      0.21s  2.72%  runtime.spanClass.sizeclass (inline)
     0.17s  2.20% 49.42%      0.61s  7.91%  runtime.scanObject
     0.11s  1.43% 50.84%      0.19s  2.46%  runtime.findObject
     0.11s  1.43% 52.27%      0.11s  1.43%  runtime.futex
     0.11s  1.43% 53.70%      0.11s  1.43%  runtime.memmove
     0.09s  1.17% 54.86%      0.09s  1.17%  internal/sync.(*Mutex).Unlock
```

### Top Memory Allocations (`pprof` -top -alloc_space)

```
Showing nodes accounting for 8893.07MB, 96.32% of 9233.05MB total
Dropped 252 nodes (cum <= 46.17MB)
      flat  flat%   sum%        cum   cum%
 3071.50MB 33.27% 33.27%  3071.50MB 33.27%  bufio.NewWriterSize
 2072.82MB 22.45% 55.72%  2072.82MB 22.45%  github.com/tokio-drift/raccoon/internal/entropy.Scan
 2007.93MB 21.75% 77.46%  2007.93MB 21.75%  github.com/tokio-drift/raccoon/internal/reassembly.(*HalfStream).pushRecent
 1050.97MB 11.38% 88.85%  1050.97MB 11.38%  bufio.NewReaderSize
  290.82MB  3.15% 92.00%   290.82MB  3.15%  github.com/tokio-drift/raccoon/internal/reassembly.(*dirSpool).Write
  170.71MB  1.85% 93.84%   173.77MB  1.88%  github.com/tokio-drift/raccoon/internal/carve.(*Scanner).Scan
   76.74MB  0.83% 94.68%    76.74MB  0.83%  github.com/tokio-drift/raccoon/internal/proto/http.(*parser).readBody
```

---

## 3. 500 MB Memory Budget Verification (PLAN 13.3)

### Acceptance Criteria
- **Pass condition**: Peak RSS ≤ 1.25 × budget (`≤ 640 MB` for 512 MB budget).
- All expected files carved with matching SHA-256 and `complete` status.
- Comparison recorded between 512 MB budget and default 2 GB budget.

### Measurements (`/usr/bin/time -v`)

| Metric | Budget: 512 MB (`--max-mem 512MB`) | Default Budget: 2 GB (`--max-mem 2GB`) | Difference / Ratio |
|---|---|---|---|
| **Peak RSS** | **546,276 KB** (533.47 MB) | **724,028 KB** (707.06 MB) | **1.04 × budget** (limit: 1.25 × 512 MB = 640 MB) |
| **Pass / Fail** | **PASS** (533.5 MB ≤ 640.0 MB) | N/A | **PASS** |
| **Pipeline Duration** | **15.030 s** | **14.978 s** | **0.052 s** (0.35%) |
| **Elapsed Wall-Clock** | **17.88 s** | **17.89 s** | **-0.01 s** (< 0.1%) |
| **Packets Analyzed** | 1,224,548 | 1,224,548 | Identical |
| **Streams Processed** | 101,564 | 101,564 | Identical |
| **Bytes Analyzed** | 504,703,662 | 504,703,662 | Identical |
| **Carved Files** | **12 / 12** | **12 / 12** | Identical (all 4 formats carved cleanly) |

### Carved Files Verification

All 12 embedded files in the 500 MB capture were extracted with `status = complete`:
- `secret.png`: SHA-256 `6c0328165683e4450da3aea197fe7edb89fe3d858473df79d896f75a975be172` (89 bytes)
- `photo.jpg`: SHA-256 `bae8839289a550db2da10bf79d22866f69dcf378291a9bd41e46c85f40d4f2b5` (685 bytes)
- `document.pdf`: SHA-256 `3b7faaf1baec9cf4bd529d52e2ac20de2bba7972743209a722a90079764c363e` (328 bytes)
- `archive.zip`: SHA-256 `83a5d482c837811e8ba564b21dc882996d1b79cf5d7c0debb59dc9b1828d8dc1` (169 bytes)

### Observations
1. **Budget Enforcement**: RACCOON's resource budget successfully capped memory usage: at `--max-mem 512MB`, peak RSS stayed at 533.5 MB (1.04 × budget, comfortably within the 1.25 × headroom limit).
2. **Wall-Time Difference**: Wall-clock performance between 512 MB budget (17.88 s) and 2 GB budget (17.89 s) showed negligible difference (< 0.1%), demonstrating that disk-backed spooling under tighter memory limits does not degrade throughput.
