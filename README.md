# RACCOON
**R**eliable and **C**onsistent **C**ybersecurity **O**ver **N**etwork  
A Network Forensics tool written in Go for attack analysis

## Prerequisites

- Go 1.22+
- Node.js 20+ and npm
- Optional: YARA (for threat intelligence rules)

## Setup

### Build everything
```bash
# Build CLI binary
make build

# Build the embedded UI
make ui
```

### Development setup
```bash
# Install web dependencies
cd web && npm ci

# Run web dev server (in separate terminal)
cd web && npm run dev
```

## Run

### Analyze a PCAP and open the UI
```bash
./bin/raccoon analyze testdata/ftp_upload_png.pcap
```
This will start the local server, open your browser to the dashboard, and print a session token in the URL.

### Run server without opening browser
```bash
./bin/raccoon analyze testdata/ftp_upload_png.pcap --no-browser
```

### Serve an existing case
```bash
./bin/raccoon serve <case-id>
```

### Run tests
```bash
# Go tests
make check

# Web tests
cd web && npm test
```

