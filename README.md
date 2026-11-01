# RACCOON

**R**eliable and **C**onsistent **C**ybersecurity **O**ver **N**etwork

A network forensics tool written in Go. Give it a `.pcap` or `.pcapng` capture
file and it rebuilds the conversations, extracts transferred files, and
generates a timeline of everything that happened — down to the raw bytes.

---

**R**eliable **a**nd **C**onsistent **C**ybersecurity **O**ver **N**etwork  
A high-performance, single-binary network forensics and PCAP analysis tool written in pure Go (cgo-free) with an embedded React investigation dashboard.

---

## Overview

RACCOON transforms raw packet captures (`.pcap` and `.pcapng`) into an interactive, structured forensic timeline. Designed for security analysts, incident responders, and network investigators, RACCOON operates entirely on your local machine with strict security boundaries:

- **Streaming Capture Reader**: Fast parsing of classic PCAP and PCAPNG files without loading entire files into memory.
- **Pure-Go TCP Reassembly**: Custom flow-sharded reassembly engine with robust out-of-order handling, duplicate detection, window-wrap support, and reassembly gap tracking.
- **Protocol Analysis**: Automated inspection and transaction pairing for HTTP/1.x (with chunked and gzip decoding), FTP control sessions, and DNS queries/responses.
- **File Carving & Anomaly Detection**: High-performance Aho-Corasick carving of embedded artifacts (JPEG, PNG, PDF, ZIP) and Shannon entropy scanning for encrypted/opaque payloads.
- **Threat Intelligence**: Local YARA rule scanning and optional VirusTotal hash reputation lookups with token-bucket rate limiting.
- **Interactive Web Dashboard**: React 18 + TypeScript SPA embedded directly into the Go binary (`//go:embed`), featuring:
  - **Storyboard**: Chronological feed with severity escalation, filtering, and deep packet evidence inspection.
  - **File Gallery**: Inspected artifacts with SHA-256 hashes, confidence scores, and safe download workflows.
  - **Stream Inspector**: Dual synchronized text and hex views with packet gutters and visual missing-data indicators.
- **Forensic Reporting**: Export self-contained HTML, structured JSON, or PDF reports directly from the CLI or UI.

---

## Installation

### Prerequisites

- **Go 1.22+**: RACCOON is built and tested with Go 1.22. Target OS is Linux (Ubuntu 22.04+); macOS and Windows are supported best-effort.
- **Optional: YARA**: The `yara` command-line binary on your system `PATH` enables local signature scanning. If omitted, YARA checks are skipped with status `not_checked`.
- **Node.js 20+ & npm**: Only required if building the embedded frontend from source.

### Install via `go install`

```bash
go install github.com/tokio-drift/raccoon/cmd/raccoon@latest
```

Ensure your `GOBIN` or `$(go env GOPATH)/bin` directory is in your system `PATH`.

### Build from Source

```bash
# Clone repository
git clone https://github.com/tokio-drift/raccoon.git
cd raccoon

# Build CLI binary with pre-compiled embedded UI
make build

# (Optional) Rebuild frontend assets and compile binary
make ui
make build
```

The resulting standalone executable will be located at `bin/raccoon`.

---

## Quick Start

### 1. Analyze a Capture and Open Web UI

Run `analyze` on any PCAP or PCAPNG capture:

```bash
raccoon analyze capture.pcap
```

RACCOON will:
1. Validate the capture headers and stream data through workers.
2. Store reassembled streams and extracted artifacts in `~/.raccoon/cases/<case-id>`.
3. Start a secure local web server on `127.0.0.1` using an ephemeral port.
4. Generate a 24-byte cryptographically secure session token.
5. Automatically launch your default web browser to the case dashboard.

### 2. Headless Analysis (No Browser)

In server, container, or remote SSH environments, disable automatic browser launching:

```bash
raccoon analyze capture.pcap --no-browser
```

The console will print the full dashboard URL with session token:
```
Dashboard: http://127.0.0.1:41235/?t=v4W5x8...
```

### 3. Serve Existing Cases / Web Dashboard

Start the web UI without analyzing a file immediately:

```bash
raccoon serve
```

Navigate to the printed URL to browse past investigation cases or upload new `.pcap` files directly through the web dropzone.

### 4. Export Reports

Generate standalone forensic reports from existing cases:

```bash
# HTML report (self-contained, no external CDN dependencies)
raccoon report <case-id> --format html

# JSON report (stable SchemaVersion 1)
raccoon report <case-id> --format json

# PDF report
raccoon report <case-id> --format pdf
```

Or generate a report directly upon analysis:

```bash
raccoon analyze capture.pcap --report html
```

### 5. Check Environment

Verify local prerequisites and case directory permissions:

```bash
raccoon doctor
```

---

## Command & Flag Reference

### `raccoon analyze <pcap>`

Analyzes a packet capture and starts the local investigation dashboard.

| Flag | Default | Description |
|---|---|---|
| `--port <int>` | `0` (random) | Port for the local HTTP server (`127.0.0.1`). |
| `--no-browser` | `false` | Do not automatically launch the system web browser. |
| `--out <dir>` | `~/.raccoon/cases` | Base directory for storing case databases and carved files. |
| `--offline` | `false` | Disable external VirusTotal API calls completely. |
| `--vt-key <string>` | `RACCOON_VT_API_KEY` | VirusTotal API key. |
| `--vt-rate <int>` | `4` | VirusTotal API rate limit in requests per minute. |
| `--rules <dir>` | embedded rules | Path to directory containing custom `.yar` / `.yara` rules. |
| `--max-file-size <size>` | `200MB` | Maximum size for an individual carved file. |
| `--max-mem <size>` | `2GB` | Memory budget cap (minimum `256MB`, e.g., `512MB`, `4GB`). |
| `--max-disk <size>` | unlimited | Maximum disk usage for spool and carved files (e.g., `10GB`). |
| `--workers <int>` | `min(CPU, 8)` | Number of worker goroutines for flow-sharded processing. |
| `--report <format>` | `""` | Generate a report (`html` or `json`) and exit without serving UI. |
| `-v`, `--verbose` | `false` | Enable verbose debug logging output (`slog`). |

### `raccoon serve`

Serves the local investigation UI for previously analyzed cases or file uploads.

| Flag | Default | Description |
|---|---|---|
| `--port <int>` | `0` (random) | Port for the local HTTP server (`127.0.0.1`). |
| `--no-browser` | `false` | Do not automatically launch the system web browser. |
| `--out <dir>` | `~/.raccoon/cases` | Base directory containing case folders. |
| `-v`, `--verbose` | `false` | Enable verbose debug logging output. |

### `raccoon report <case-id-or-path>`

Generates an investigation report from an existing case directory.

| Flag | Default | Description |
|---|---|---|
| `--format <format>` | `html` | Report format: `html`, `json`, or `pdf`. |
| `--out <dir>` | `~/.raccoon/cases` | Base directory to search if `<case-id>` is provided. |

### `raccoon doctor`

Runs diagnostic probes on the local runtime environment.

| Flag | Default | Description |
|---|---|---|
| `--out <dir>` | `~/.raccoon/cases` | Case directory path to inspect. |

### `raccoon version`

Prints the compiled module version, Git revision, and build timestamp.

### `raccoon debug dump-stream <pcap> <stream-index> [c2s|s2c]`

Dumps raw reassembled TCP stream payloads in hexadecimal.

| Flag | Default | Description |
|---|---|---|
| `--pcap <path>` | `""` | Path to the PCAP file. |
| `--stream <int>` | `0` | Zero-based TCP stream index (matching Wireshark/tshark). |
| `--dir <string>` | `both` | Stream direction: `c2s`, `s2c`, or `both`. |

---

## Resource Tuning Guidance

RACCOON incorporates a built-in memory accountant and soft runtime memory limits (`debug.SetMemoryLimit`) to prevent Out-Of-Memory (OOM) crashes on large captures.

### Memory Budget (`--max-mem`)

The `--max-mem` flag configures the total memory budget. The default is `2GB` and the minimum allowed is `256MB`:

```bash
# Low-memory embedded/container environment
raccoon analyze traffic.pcap --max-mem 512MB --workers 2

# High-throughput workstation environment
raccoon analyze large_traffic.pcap --max-mem 8GB --workers 8
```

RACCOON automatically derives internal pool shares from the specified memory budget:
- **40% for stream reassembly buffers**: Pending out-of-order buffers are capped per half-stream. Streams exceeding 1 MB are spilled to disk spools in `~/.raccoon/cases/<id>/streams/`.
- **15% for packet decode and HTTP decompression**: Decoders and decompression buffers (gzip/chunked) are capped.
- **15% for database batch buffers**: SQLite transactions batch writes to minimise memory and disk overhead.
- **30% headroom**: Reserved for runtime garbage collection and operating system buffers.

### Disk Usage Cap (`--max-disk`)

By default, disk usage is unbounded. Use `--max-disk` to prevent filling storage partitions during deep forensic reconstruction:

```bash
raccoon analyze capture.pcap --max-disk 20GB
```

---

## Privacy Notice

RACCOON is engineered with a strict **local-first privacy architecture**:

1. **No Traffic Exfiltration**: Packet capture payloads, IP addresses, credentials, URLs, and carved file contents are **never** transmitted over the network.
2. **VirusTotal Lookups Send Hashes Only**: When threat intelligence lookups are enabled, RACCOON queries VirusTotal using the SHA-256 hash of carved files (`GET /api/v3/files/{sha256}`). The file bytes themselves are never uploaded.
3. **Full Offline Mode**: Use the `--offline` flag to guarantee zero outbound network traffic:
   ```bash
   raccoon analyze capture.pcap --offline
   ```
   When offline, external API lookups are skipped and file verdicts are recorded as `not_checked`.

---

## Safety & Security Notice

RACCOON treats all input PCAP files as potentially hostile:

- **Carved File Permissions**: All extracted artifacts written to disk in `<case-dir>/carved/<sha256>.<ext>` are assigned read-only mode `0400` inside a directory restricted to mode `0700`.
- **Inert Artifacts**: Carved files are inert forensic artifacts. **Never execute or open carved files directly** outside of a safe sandbox. RACCOON's web interface does not render or preview carved file contents.
- **Filename Sanitization**: Remote-supplied filenames (from HTTP headers or FTP commands) are sanitized and treated purely as metadata for display; they are never used as filesystem paths.
- **Path Traversal Protection**: All internal file access queries validate path boundaries and prevent traversal attempts (`../`).
- **Standardized Verdict Vocabulary**: To maintain forensic integrity, RACCOON **never uses the word "safe"** to describe any file or traffic. The allowed verdict states are:
  - `malicious`: Confirmed threat detection by YARA or VirusTotal.
  - `suspicious`: Minor positive detections or suspicious characteristics.
  - `no_detections`: Scanned with no indicators found (not guaranteed safe).
  - `unknown`: Hash not recognized by threat intelligence databases.
  - `not_checked`: File was not checked (offline mode or absent API key).

---

## Web Dashboard & Screenshots

The embedded single-page application provides a modern, responsive interface for deep forensic analysis:

### 1. Investigation Storyboard
Interactive chronological feed of connection milestones, protocol commands, file extractions, and threat events with non-colour cues and severity badges (`info`, `warning`, `critical`).
> *[ Screenshot Placeholder: Chronological Storyboard with filtered events and detail pane ]*

### 2. Carved Files Gallery
Comprehensive listing of reconstructed files with extraction status, SHA-256 hashes, YARA/VT verdicts, and safe download modals.
> *[ Screenshot Placeholder: File Gallery with artifact table and safe download dialog ]*

### 3. Stream Byte Inspector
Synchronized UTF-8 text and hexadecimal inspection panes with packet gutters, directional filtering, gap notifications, and carved range highlighting.
> *[ Screenshot Placeholder: Synchronized dual-pane Stream Inspector with byte window ]*

### 4. Case Overview & Status
Real-time analysis progress stepper, protocol breakdowns, and forensic summary statistics.
> *[ Screenshot Placeholder: Case processing view and empty dashboard dropzone ]*

---

## Troubleshooting

Run the built-in diagnostic tool to identify environment issues:

```bash
raccoon doctor
```

### Common Issues & Resolutions

| Issue | Cause | Solution |
|---|---|---|
| `yara: warning (not found)` | `yara` binary is not in system `PATH`. | Install YARA (`sudo apt install yara` on Ubuntu) or continue without YARA (rule scanning will be disabled). |
| `case directory: failed` | Cannot write to `~/.raccoon/cases`. | Verify directory permissions or specify an alternative path with `--out <path>`. |
| `localhost: failed` | Unable to bind to `127.0.0.1`. | Check if another process is conflicting or if loopback interface configuration is restricted. |
| `carved files: warning (mount is not noexec)` | Case directory partition allows execution. | Advisory warning. Ensure carved files are not executed manually, or mount case storage with `noexec`. |
| `Port already in use` | Chosen `--port` is occupied. | Omit `--port` to let RACCOON choose a random free loopback port automatically. |
| `Out of memory / OOM` | High concurrent load on large PCAP. | Reduce worker count and memory budget: `raccoon analyze capture.pcap --max-mem 1GB --workers 2`. |
| `VirusTotal rate limit exceeded` | Free API key quota exceeded. | Adjust `--vt-rate` (e.g. `--vt-rate 4` for standard public tier) or run with `--offline`. |
| `Browser failed to launch` | Running on headless server or WSL without X/Wayland. | Pass `--no-browser` and copy the printed dashboard URL into your browser. |

---

## Release Checklist

Before tagging or distributing a new release of RACCOON, run the automated release checklist:

```bash
make release-check
# or execute directly:
./scripts/release_check.sh
```

The release checklist verifies the following five critical criteria:
1. **Frontend Build (`make ui`)**: Rebuilds the embedded React 18 / TypeScript single-page application into `web/dist`.
2. **Distribution Freshness (`scripts/check_dist.sh`)**: Validates that the committed `web/dist` matches a clean rebuild from source and is not stale.
3. **Code Quality and Tests (`make check`)**: Ensures all Go files adhere to formatting standards (`gofmt -s`), pass static analysis (`go vet ./...`), and pass all unit, integration, and golden tests (`go test ./...`).
4. **Module Path Integrity**: Verifies that the `go.mod` module path strictly matches `github.com/tokio-drift/raccoon`.
5. **CGO-Free Standalone Build**: Verifies that the binary compiles cleanly in pure Go without CGO dependencies (`CGO_ENABLED=0 go build ./cmd/raccoon`), ensuring static portability across Linux systems.

---

## License

This project is licensed under the terms described in the [LICENSE](LICENSE) file.
