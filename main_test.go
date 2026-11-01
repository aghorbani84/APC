package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParsePorts(t *testing.T) {
	ports, err := parsePorts("443, 80, 22-24,23")
	if err != nil || !reflect.DeepEqual(ports, []int{22, 23, 24, 80, 443}) {
		t.Fatalf("got %v, %v", ports, err)
	}
	for _, spec := range []string{"", "0", "65536", "-1", "80,", "abc", "90-80", "1-65536", "1-2-3", "1-"} {
		t.Run(spec, func(t *testing.T) {
			if _, err := parsePorts(spec); err == nil {
				t.Fatalf("accepted invalid ports %q", spec)
			}
		})
	}
	ports, err = parsePorts("1-65535")
	if err != nil || len(ports) != 65535 {
		t.Fatalf("full range: %d ports, %v", len(ports), err)
	}
}

func listen(t *testing.T, network, address string) int {
	t.Helper()
	listener, err := net.Listen(network, address)
	if err != nil {
		if network == "tcp6" {
			t.Skipf("IPv6 unavailable: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

func TestScanPort(t *testing.T) {
	for _, tc := range []struct{ network, host string }{{"tcp4", "127.0.0.1"}, {"tcp6", "::1"}} {
		t.Run(tc.network, func(t *testing.T) {
			port := listen(t, tc.network, net.JoinHostPort(tc.host, "0"))
			result := ScanPort(tc.network, tc.host, port, time.Second)
			if !result.IsOpen || result.StateString() != "Open" || result.Port != port || result.Hostname != tc.host {
				t.Fatalf("unexpected result: %+v", result)
			}
			result = scanPort(context.Background(), tc.host, port, time.Second)
			if !result.IsOpen {
				t.Fatalf("context scanner failed: %+v", result)
			}
		})
	}
}

func TestClosedAndUnsupportedPorts(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	result := ScanPort("tcp", "127.0.0.1", port, time.Second)
	if result.IsOpen || result.StateString() != "Closed" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if ScanPort("udp", "127.0.0.1", port, time.Second).IsOpen {
		t.Fatal("UDP dial must not be reported as an open TCP port")
	}
}

func TestScanDeduplicatesAndSorts(t *testing.T) {
	port := listen(t, "tcp4", "127.0.0.1:0")
	results, err := scan(context.Background(), []string{"127.0.0.1", "127.0.0.1"}, []int{port, 1}, 2, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[0].Port != 1 || results[1].Port != port || !results[1].IsOpen {
		t.Fatalf("unexpected results: %+v", results)
	}
}

func TestScanValidation(t *testing.T) {
	for _, tc := range []struct {
		workers int
		wait    time.Duration
		ports   []int
	}{
		{0, time.Second, []int{80}},
		{1025, time.Second, []int{80}},
		{1, 0, []int{80}},
		{1, -time.Second, []int{80}},
		{1, time.Second, []int{0}},
		{1, time.Second, nil},
	} {
		if _, err := scan(context.Background(), []string{"127.0.0.1"}, tc.ports, tc.workers, tc.wait); err == nil {
			t.Fatalf("accepted invalid config: %+v", tc)
		}
	}
	if _, err := scan(context.Background(), nil, []int{80}, 1, time.Second); err == nil {
		t.Fatal("accepted empty hosts")
	}
	// A malformed literal fails locally without relying on external DNS.
	if _, err := scan(context.Background(), []string{"bad host!"}, []int{80}, 1, time.Second); err == nil {
		t.Fatal("accepted invalid hostname")
	}
}

func TestScanCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := scan(ctx, []string{"127.0.0.1"}, []int{80, 443}, 2, time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestRunJSON(t *testing.T) {
	port := listen(t, "tcp4", "127.0.0.1:0")
	var out, errOut bytes.Buffer
	err := run(context.Background(), []string{"-json", "-ports", strconv.Itoa(port), "127.0.0.1"}, strings.NewReader(""), &out, &errOut)
	if err != nil {
		t.Fatal(err)
	}
	var results []ScanResult
	if err := json.Unmarshal(out.Bytes(), &results); err != nil {
		t.Fatalf("invalid JSON %q: %v", out.String(), err)
	}
	if len(results) != 1 || !results[0].IsOpen || results[0].Port != port {
		t.Fatalf("unexpected results: %+v", results)
	}
}

func TestRunOptions(t *testing.T) {
	for _, args := range [][]string{
		{"-ports", "0"}, {"-workers", "0"}, {"-timeout", "0s"}, {"-unknown"},
	} {
		if err := run(context.Background(), args, strings.NewReader(""), io.Discard, io.Discard); err == nil {
			t.Fatalf("accepted invalid options: %v", args)
		}
	}
	if err := run(context.Background(), []string{"-help"}, strings.NewReader(""), io.Discard, io.Discard); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("help: %v", err)
	}
}

func TestRunAllAndEmptyJSON(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	for _, all := range []bool{false, true} {
		var out bytes.Buffer
		args := []string{"-json", "-ports", strconv.Itoa(port)}
		if all {
			args = append(args, "-all")
		}
		args = append(args, "127.0.0.1")
		if err := run(context.Background(), args, strings.NewReader(""), &out, io.Discard); err != nil {
			t.Fatal(err)
		}
		var results []ScanResult
		if err := json.Unmarshal(out.Bytes(), &results); err != nil {
			t.Fatal(err)
		}
		if all && (len(results) != 1 || results[0].IsOpen) {
			t.Fatalf("expected one closed port: %s", out.String())
		}
		if !all && out.String() != "[]\n" {
			t.Fatalf("expected empty JSON array, got %q", out.String())
		}
	}
}

func TestScanCancellationDuringConnections(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	accepted := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			conn.Close()
			close(accepted)
			cancel()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	ports := make([]int, 1000)
	for i := range ports {
		ports[i] = port
	}
	_, err = scan(ctx, []string{"127.0.0.1"}, ports, 2, time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation during scan, got %v", err)
	}
	select {
	case <-accepted:
	default:
		t.Fatal("scan never connected")
	}
}

func TestRunInteractiveDefault(t *testing.T) {
	for _, input := range []string{"", "\n"} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var out bytes.Buffer
		err := run(ctx, nil, strings.NewReader(input), &out, io.Discard)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected cancellation, got %v", err)
		}
		if !strings.Contains(out.String(), "leave blank for localhost") {
			t.Fatalf("missing interactive prompt: %q", out.String())
		}
	}
}

func TestRunText(t *testing.T) {
	port := listen(t, "tcp4", "127.0.0.1:0")
	var out bytes.Buffer
	err := run(context.Background(), []string{"-ports", strconv.Itoa(port), "127.0.0.1"}, strings.NewReader(""), &out, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "is Open\n") || !strings.Contains(out.String(), "1 open of 1 scanned ports") {
		t.Fatalf("unexpected text output: %q", out.String())
	}
	if strings.Contains(out.String(), "\033") {
		t.Fatal("output should not contain ANSI escapes")
	}
}
