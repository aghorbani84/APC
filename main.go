// APC is a TCP connect scanner for systems you own or are authorized to test.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const maxPortNumber = 444

var timeout = 500 * time.Millisecond

// ScanResult describes one TCP connection attempt. Closed also includes attempts
// that timed out or failed; a TCP connect scan cannot distinguish these states.
type ScanResult struct {
	Port     int    `json:"port"`
	IsOpen   bool   `json:"is_open"`
	Protocol string `json:"protocol"`
	Hostname string `json:"hostname"`
}

func (sr ScanResult) StateString() string {
	if sr.IsOpen {
		return "Open"
	}
	return "Closed"
}

func scanPort(ctx context.Context, hostname string, port int, wait time.Duration) ScanResult {
	result := ScanResult{Port: port, Protocol: "tcp", Hostname: hostname}
	dialer := net.Dialer{Timeout: wait}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(hostname, strconv.Itoa(port)))
	if err == nil {
		result.IsOpen = true
		conn.Close()
	}
	return result
}

// ScanPort attempts one connection. Only TCP variants are supported: a successful
// UDP dial is not evidence that a remote port is open.
func ScanPort(protocol, hostname string, port int, wait time.Duration) ScanResult {
	if protocol != "tcp" && protocol != "tcp4" && protocol != "tcp6" {
		return ScanResult{Port: port, Protocol: protocol, Hostname: hostname}
	}
	result := ScanResult{Port: port, Protocol: protocol, Hostname: hostname}
	if port < 1 || port > 65535 || wait <= 0 {
		return result
	}
	conn, err := net.DialTimeout(protocol, net.JoinHostPort(hostname, strconv.Itoa(port)), wait)
	if err == nil {
		result.IsOpen = true
		conn.Close()
	}
	return result
}

// parsePorts accepts comma-separated ports and inclusive ranges.
func parsePorts(spec string) ([]int, error) {
	seen := make(map[int]bool)
	for _, part := range strings.Split(spec, ",") {
		bounds := strings.Split(strings.TrimSpace(part), "-")
		if len(bounds) > 2 {
			return nil, fmt.Errorf("invalid port range %q", part)
		}
		start, err := strconv.Atoi(strings.TrimSpace(bounds[0]))
		if err != nil || start < 1 || start > 65535 {
			return nil, fmt.Errorf("invalid port %q (expected 1–65535)", part)
		}
		end := start
		if len(bounds) == 2 {
			end, err = strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err != nil || end < start || end > 65535 {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
		}
		for port := start; port <= end; port++ {
			seen[port] = true
		}
	}
	ports := make([]int, 0, len(seen))
	for port := range seen {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports, nil
}

// scan resolves every target before starting any connections, then scans each
// unique resolved address with a bounded worker pool.
func scan(ctx context.Context, hosts []string, ports []int, workers int, wait time.Duration) ([]ScanResult, error) {
	if workers < 1 || workers > 1024 {
		return nil, errors.New("workers must be between 1 and 1024")
	}
	if wait <= 0 {
		return nil, errors.New("timeout must be positive")
	}
	if len(hosts) == 0 || len(ports) == 0 {
		return nil, errors.New("at least one host and port are required")
	}
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port %d", port)
		}
	}
	var addresses []string
	seen := make(map[string]bool)
	for _, host := range hosts {
		ips, err := net.DefaultResolver.LookupHost(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve %q: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("resolve %q: no addresses found", host)
		}
		for _, ip := range ips {
			if !seen[ip] {
				seen[ip] = true
				addresses = append(addresses, ip)
			}
		}
	}
	type job struct {
		host string
		port int
	}
	jobs := make(chan job)
	results := make(chan ScanResult)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case task, ok := <-jobs:
					if !ok {
						return
					}
					result := scanPort(ctx, task.host, task.port, wait)
					select {
					case results <- result:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, host := range addresses {
			for _, port := range ports {
				select {
				case jobs <- job{host, port}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()
	output := make([]ScanResult, 0)
	for result := range results {
		output = append(output, result)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sort.Slice(output, func(i, j int) bool {
		if output[i].Hostname == output[j].Hostname {
			return output[i].Port < output[j].Port
		}
		return output[i].Hostname < output[j].Hostname
	})
	return output, nil
}

// InitialScan retains the original convenience entry point with bounded concurrency.
func InitialScan(hosts ...string) {
	ports, _ := parsePorts(fmt.Sprintf("1-%d", maxPortNumber))
	results, err := scan(context.Background(), hosts, ports, 100, timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	for _, result := range results {
		fmt.Printf("Port %d (%s on %s) is %s\n", result.Port, result.Protocol, result.Hostname, result.StateString())
	}
}

func run(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("apc", flag.ContinueOnError)
	flags.SetOutput(errOut)
	portSpec := flags.String("ports", "1-444", "ports or inclusive ranges, e.g. 22,80,443,8000-8100")
	workers := flags.Int("workers", 100, "concurrent connections (1–1024)")
	wait := flags.Duration("timeout", timeout, "timeout per connection, e.g. 500ms or 2s")
	all := flags.Bool("all", false, "include closed/failed ports")
	jsonOutput := flags.Bool("json", false, "output a JSON array (no color or progress text)")
	flags.Usage = func() {
		fmt.Fprintln(errOut, "Usage: apc [options] [host ...]\nScan only systems you own or have permission to test.\nOptions must precede hosts.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	ports, err := parsePorts(*portSpec)
	if err != nil {
		return err
	}
	hosts := flags.Args()
	if len(args) == 0 {
		fmt.Fprint(out, "Enter the hostname or IP address to scan (leave blank for localhost): ")
		line, err := bufio.NewReader(in).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("read hostname: %w", err)
		}
		hosts = strings.Fields(line)
	}
	if len(hosts) == 0 {
		hosts = []string{"localhost"}
	}
	results, err := scan(ctx, hosts, ports, *workers, *wait)
	if err != nil {
		return err
	}
	visible := make([]ScanResult, 0)
	for _, result := range results {
		if *all || result.IsOpen {
			visible = append(visible, result)
		}
	}
	if *jsonOutput {
		return json.NewEncoder(out).Encode(visible)
	}
	for _, result := range visible {
		if _, err := fmt.Fprintf(out, "Port %d (%s on %s) is %s\n", result.Port, result.Protocol, result.Hostname, result.StateString()); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(out, "Scan complete: %d open of %d scanned ports.\n", countOpen(results), len(results))
	return err
}

func countOpen(results []ScanResult) int {
	count := 0
	for _, result := range results {
		if result.IsOpen {
			count++
		}
	}
	return count
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
