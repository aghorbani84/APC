# APC — Abolfazl Port Scanner

A dependency-free TCP connect scanner written in Go. Scan IPv4 and IPv6 targets
with bounded concurrency, configurable port ranges, and optional JSON output.

**Only scan systems you own or have explicit permission to test.**

## Install and run

Install [Go](https://go.dev/dl/) 1.22 or newer, then:

```sh
git clone https://github.com/aghorbani84/APC.git
cd APC
go build -o apc .
./apc -help
```

On Windows, use `go build -o apc.exe .` and run `apc.exe`.
You can also run from source with `go run .`, or install directly:

```sh
go install github.com/aghorbani84/APC@latest
```

Direct installation uses the latest published repository version, which may not
include changes on an unmerged branch. The executable is installed in `GOBIN`
(or `$(go env GOPATH)/bin` by default); add that directory to your `PATH`.

## Usage

```text
apc [options] [host ...]
```

**Place options before host arguments.** Run without arguments for an interactive
hostname prompt; a blank response (or end of input) selects `localhost`. With
options but no hosts, APC uses `localhost` without prompting.

```sh
# Interactive mode (ports 1–444)
./apc

# Scan selected ports on a local system
./apc -ports 22,80,443,8000-8100 127.0.0.1

# Scan multiple targets, including IPv6 (no brackets around the address)
./apc -ports 80,443 -workers 50 -timeout 1s 127.0.0.1 ::1

# Include unsuccessful connection attempts
./apc -ports 1-1024 -all localhost

# Machine-readable output
./apc -ports 22,80,443 -json 127.0.0.1 > results.json
```

| Option | Default | Description |
| --- | --- | --- |
| `-ports` | `1-444` | Comma-separated ports and inclusive ranges, from 1 to 65535 |
| `-workers` | `100` | Maximum concurrent connection attempts, from 1 to 1024 |
| `-timeout` | `500ms` | Positive timeout per TCP connection, such as `250ms` or `2s` |
| `-all` | `false` | Include closed/failed ports, not only open ports |
| `-json` | `false` | Emit a JSON array with no prompts, progress text, or color |
| `-help` | | Show usage |

All resolved IPv4 and IPv6 addresses are scanned. Duplicate resolved addresses
and overlapping CLI port ranges are scanned only once. Results are sorted by
address (lexically), then by port. Text output ends with a summary; JSON emits
an array (including `[]` when no matching ports were found):

```json
[{"port":80,"is_open":true,"protocol":"tcp","hostname":"127.0.0.1"}]
```

The `hostname` field contains the resolved IP address. `is_open: false` means
that a TCP connection could not be established: the port may be closed,
filtered, unreachable, or timed out. APC does not perform UDP scanning, service
detection, or vulnerability testing. No elevated privileges are needed.

Press **Ctrl+C** to cancel outstanding connections. Cancellation, invalid input,
and DNS resolution errors produce a diagnostic on stderr and a nonzero exit
status. A completed scan exits successfully even if no ports are open. Results
are buffered until completion; cancellation does not emit a partial report.
The timeout is per connection, not a whole-scan deadline.

## Development

No third-party Go dependencies are required. Tests only connect to local
loopback listeners; the IPv6 test skips if IPv6 is unavailable.

```sh
gofmt -w main.go main_test.go
go vet ./...
go test -race ./...
go build ./...
```

GitHub Actions runs formatting checks, vet, tests, and a build on the minimum
supported Go version and the latest stable Go version. A separate job runs the
race detector on the latest stable version.

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).
