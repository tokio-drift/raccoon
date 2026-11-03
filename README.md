# RACCOON

**RACCOON** is a network forensics tool. Give it a saved network capture (`.pcap` or `.pcapng`) and it helps you understand the conversations inside it, recover supported files, and review the evidence in a local browser dashboard or report.

It is designed for analysts and students who want to investigate network traffic without manually examining every packet.

## What it does

- Reads classic PCAP and PCAPNG files.
- Groups TCP and UDP packets into network conversations.
- Rebuilds TCP data in the right order and marks missing or conflicting data.
- Analyzes supported FTP, HTTP, and DNS traffic.
- Searches traffic for supported file types, including JPEG, PNG, PDF, and ZIP.
- Scans recovered files with YARA when the YARA command-line tool and rules are available.
- Optionally checks recovered file hashes with VirusTotal.
- Stores each investigation as a case that can be explored in the dashboard or exported as a report.

YARA and VirusTotal results are file checks. A “no detections” result does not prove a file is safe. RACCOON also records network events and anomalies, which help an analyst investigate; these should not be confused with a complete automated attack-detection system.

## How the workflow works

Think of a capture as a recording of many small packets from different conversations, mixed together.

1. **Read packets:** RACCOON validates the capture and reads packets incrementally.
2. **Group conversations:** It decodes addresses and ports and groups related packets into flows.
3. **Rebuild TCP streams:** TCP data is split across segments. RACCOON uses sequence numbers to put bytes in order, handles retransmissions, and marks gaps if the capture is missing data.
4. **Analyze protocols:** It interprets supported FTP, HTTP, and DNS messages and creates timeline events.
5. **Recover files:** It searches stream contents for supported file signatures and uses file-format rules to find file boundaries. This can find files even on unusual ports.
6. **Save and show results:** RACCOON stores the case and artifacts, then serves the dashboard locally or exports a report.

## Requirements

- Go 1.22 or newer to build the backend.
- A prebuilt frontend is included in `web/dist/`, so Node.js and npm are only needed if you want to rebuild the frontend.
- YARA is optional. Without it, YARA scanning is unavailable or marked not checked.
- VirusTotal is optional and requires an API key and internet access. You can disable online lookups with `--offline`.

## Set up YARA and VirusTotal (optional)

These are two separate checks on recovered files. YARA scans the file locally using rules. VirusTotal checks the file's SHA-256 hash online.

### YARA

Install the YARA command-line program for your operating system and make sure the `yara` command is available in your terminal's `PATH`. RACCOON includes default rules, but it still needs the YARA program installed to run them. If YARA is missing, the analysis can continue, but YARA verdicts will be unavailable or shown as `not checked`.

To use your own YARA rules, put them in a directory and pass that directory to RACCOON:

```bash
./bin/raccoon analyze capture.pcap --rules path/to/yara-rules
```

### VirusTotal

To enable VirusTotal lookups, obtain an API key from VirusTotal and provide it to RACCOON. The preferred method is an environment variable:

```bash
export RACCOON_VT_API_KEY="your-api-key"
./bin/raccoon analyze capture.pcap
```

You can also pass the key directly with `--vt-key`, but avoid saving a real key in shell history or sharing it in screenshots. RACCOON sends the file's SHA-256 hash for a reputation lookup; it does not upload the recovered file for this lookup. The default request limit is 4 lookups per minute and can be changed with `--vt-rate`.

To run without online lookups, use:

```bash
./bin/raccoon analyze capture.pcap --offline
```

When VirusTotal has no result for a hash, the verdict can be `unknown`. A YARA result of `no detections` means no configured rule matched. Neither result proves the file is harmless.

## Build from source

Open a terminal in this folder, the `raccoon` project directory:

```bash
go version
make build
```

The executable is created at `bin/raccoon`. Check the build with:

```bash
./bin/raccoon version
```

To rebuild the web interface as well, install Node.js and npm, then run:

```bash
make ui
make build
```

The built web assets are embedded in the Go program, so users can run the binary without a separate frontend server.

## Run an analysis

Analyze a capture and open the dashboard:

```bash
./bin/raccoon analyze testdata/http_get_jpeg_chunked.pcap
```

RACCOON prints progress, creates a case under `~/.raccoon/cases` by default, and opens a local dashboard. You can also run:

```bash
./bin/raccoon analyze path/to/capture.pcap --offline
```

Useful options include:

- `--offline`: disable VirusTotal lookups.
- `--no-browser`: do not open a browser automatically; RACCOON still prints the dashboard address.
- `--out DIR`: choose where case folders are saved.
- `--max-mem SIZE`: set the memory budget, for example `512MB` or `2GB`.
- `--max-disk SIZE`: set a disk usage limit. If omitted, disk use is unlimited and RACCOON prints a warning.
- `--workers N`: choose the number of packet-processing workers.

The dashboard address contains a session token after `?t=`. Treat that address like a password: do not share it in screenshots or messages while the server is running.

To analyze and write a report without starting the dashboard, use `--report`:

```bash
./bin/raccoon analyze testdata/http_get_jpeg_chunked.pcap --offline --report json
```

The `analyze --report` option supports HTML and JSON. For reports from an existing case, see below.

## Explore the dashboard

The dashboard has three main investigation views:

- **Storyboard:** a chronological list of observed events. Event cards show the time, protocol, endpoints, severity, and packet evidence when available.
- **Files:** recovered artifacts with format, size, direction, extraction status, confidence, hashes, and available malware verdicts. RACCOON does not automatically preview recovered files.
- **Streams:** reconstructed conversation data in each direction. The text view shows readable bytes; the hex view shows exact byte values. Packet and byte navigation help locate evidence in a long stream.

A stream is one tracked network conversation. Its stream ID is an internal label used to connect events and files to that conversation. File extraction confidence describes how complete the recovery is; it is separate from the malware verdict.

RACCOON normally serves the dashboard at `127.0.0.1`, which means “this computer.” The browser and RACCOON communicate locally. Optional VirusTotal lookups are a separate online feature.

## Export a report from a saved case

After an analysis, use the case ID printed by RACCOON:

```bash
./bin/raccoon report CASE_ID --format pdf
```

Supported formats are `html`, `json`, and `pdf`. Reports summarize case metadata, recovered artifacts, verdicts, and the event timeline.

## Other commands

```bash
./bin/raccoon serve                 # open the dashboard for saved cases or uploads
./bin/raccoon doctor                # check the local environment and case directory
./bin/raccoon version               # show build information
./bin/raccoon debug dump-stream testdata/tcp_basic.pcap 0 c2s
```

For all options, run `./bin/raccoon --help` or `./bin/raccoon COMMAND --help`.

## Project structure

```text
cmd/raccoon/       Program entry point
internal/capture/  PCAP and PCAPNG reading and packet indexing
internal/decode/   Packet header decoding
internal/flow/     TCP and UDP conversation tracking
internal/reassembly/ TCP stream reconstruction
internal/proto/    FTP, HTTP, and DNS analyzers
internal/carve/    File signature scanning and format handlers
internal/entropy/  High-entropy region scanning
internal/intel/    YARA and optional VirusTotal checks
internal/pipeline/ Coordinates the analysis stages
internal/store/    SQLite case database
internal/casedir/  Case folder creation and paths
internal/server/   Local API and embedded dashboard server
internal/cli/      Command-line commands
internal/report/   HTML, JSON, and PDF reports
internal/model/    Shared event, stream, file, and verdict data types
web/src/           React and TypeScript dashboard source
web/dist/          Built dashboard embedded in the executable
testdata/          Sample captures, generators, and expected outputs
rules/             Default YARA rules
scripts/           Build, validation, and release helpers
docs/              API, performance, and validation notes
```

The rest of `internal/` contains supporting packages for resource limits, logging, version details, timelines, and test helpers.

## Learn with the sample capture

The sample `testdata/http_get_jpeg_chunked.pcap` contains a short HTTP request and response. RACCOON identifies the transaction, recovers `img.jpg`, links the event to its stream, and includes both in the case report.

The parent folder may also contain these learning guides:

- [Understand the project](../Understand.md)
- [Step-by-step example walkthrough](../example.md)
- [Implementation plan and phase history](../PLAN.md)

## Developer checks

Run the project checks with:

```bash
make check
```

This runs formatting checks, `go vet`, and Go tests. To run only the tests:

```bash
make test
```

To regenerate the deterministic sample captures:

```bash
make testdata
```

## Data handling

Capture analysis and case storage happen on your computer. The local dashboard is protected by a session token. If VirusTotal is enabled, RACCOON sends file hashes for reputation lookups; it does not need to upload the recovered file for that hash lookup. Use `--offline` to disable those requests.

Captured traffic can contain sensitive information, including credentials sent in cleartext. Protect case folders and exported reports accordingly.

## License

See [LICENSE](LICENSE).
