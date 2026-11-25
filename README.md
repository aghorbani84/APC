# APC — Abolfazl Port Scanner

> A small, dependency-free TCP connect scanner in Go — built for learning and for checking hosts you own or are authorized to test.

[![Go CI](https://github.com/aghorbani84/APC/actions/workflows/ci.yml/badge.svg)](https://github.com/aghorbani84/APC/actions/workflows/ci.yml)
![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue)](LICENSE)

> [!IMPORTANT]
> **Only scan systems you own or have explicit, written permission to test.** Unauthorized scanning may be illegal and is against the terms of most networks and providers.

## Overview

APC is a learning-oriented network-administration tool. It attempts plain TCP connections to a list of ports on one or more hosts and reports which ones accept a connection. It is useful for auditing your own machines, lab VMs, or home network, and as a readable example of bounded concurrency in Go.

It does **not** do UDP scanning, service/version detection, OS fingerprinting, or vulnerability testing, and it needs no elevated privileges.

## Features

- **TCP connect scan** over IPv4 and IPv6 (every resolved address of a host is scanned)
- **Flexible port specs** — comma-separated ports and inclusive ranges (`22,80,443,8000-8100`); duplicates and overlaps are scanned once
- **Bounded worker pool** — configurable concurrency (1–1024) and per-connection timeout
- **JSON output** for scripting, or human-readable text with a summary line
- **Interactive mode** — run with no arguments to be prompted for a host (blank = `localhost`)
- **Clean cancellation** — `Ctrl+C` stops outstanding connections and exits non-zero
- **Zero third-party dependencies** — standard library only

## Tech Stack

- Go 1.22+ (standard library: `net`, `context`, `flag`, `encoding/json`, `sync`)
- GitHub Actions CI: `gofmt`, `go vet`, tests on Go 1.22 and stable, plus a race-detector job

## Getting Started

### Build from source

```sh
git clone https://github.com/aghorbani84/APC.git
cd APC
go build -o apc .
./apc -help
```

On Windows, use `go build -o apc.exe .` and run `apc.exe`. You can also run directly with `go run .`.

### Install with `go install`

```sh
go install github.com/aghorbani84/APC@latest
```

The binary is placed in `GOBIN` (or `$(go env GOPATH)/bin`); make sure that directory is on your `PATH`.

## Usage

```text
apc [options] [host ...]
```

Options must come **before** host arguments. With options but no hosts, APC scans `localhost`.

```sh
# Interactive mode (default ports 1–444)
./apc

# Selected ports on your own machine
./apc -ports 22,80,443,8000-8100 127.0.0.1

# Several targets, including IPv6 (no brackets)
./apc -ports 80,443 -workers 50 -timeout 1s 127.0.0.1 ::1

# Include ports that did not accept a connection
./apc -ports 1-1024 -all localhost

# Machine-readable output
./apc -ports 22,80,443 -json 127.0.0.1 > results.json
```

| Option | Default | Description |
| --- | --- | --- |
| `-ports` | `1-444` | Ports and inclusive ranges, 1–65535 |
| `-workers` | `100` | Max concurrent connection attempts, 1–1024 |
| `-timeout` | `500ms` | Timeout per TCP connection (e.g. `250ms`, `2s`) |
| `-all` | `false` | Also list closed/failed ports |
| `-json` | `false` | Emit a JSON array (no prompts, progress text, or color) |
| `-help` | | Show usage |

Example JSON:

```json
[{"port":80,"is_open":true,"protocol":"tcp","hostname":"127.0.0.1"}]
```

`hostname` holds the resolved IP address. `is_open: false` means no TCP connection could be established — the port may be closed, filtered, unreachable, or timed out. Results are sorted by address, then port, and are printed once the scan completes.

## Development

```sh
gofmt -l .          # should print nothing
go vet ./...
go test -race ./...
go build ./...
```

Tests only connect to local loopback listeners; the IPv6 test is skipped if IPv6 is unavailable.

## Project Structure

```text
APC/
├── main.go          # CLI, port parsing, resolver and worker-pool scanner
├── main_test.go     # Unit and loopback integration tests
├── go.mod           # Module definition (Go 1.22)
└── .github/workflows/ci.yml
```

## License

Released under the [GNU General Public License v3.0](LICENSE).

## Author

Built by [@aghorbani84](https://github.com/aghorbani84).
