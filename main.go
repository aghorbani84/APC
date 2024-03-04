package main

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

const maxPortNumber = 444

var timeout = 500 * time.Millisecond

// ScanResult represents the result of a port scan, storing the port number and its state.
type ScanResult struct {
	Port     int    // Port number
	IsOpen   bool   // Port state (Open or Closed)
	Protocol string // Protocol used for scanning
	Hostname string // Hostname being scanned
}

// colorizeOutput adds color to the output for better readability and charm.
func (sr ScanResult) colorizeOutput() string {
	color := "\033[32m" // Green for open ports
	if !sr.IsOpen {
		color = "\033[31m" // Red for closed ports
	}
	return fmt.Sprintf("%sPort %d (%s on %s) is %s\n", color, sr.Port, sr.Protocol, sr.Hostname, sr.StateString()) + "\033[0m"
}

// StateString returns a human-readable state representation.
func (sr ScanResult) StateString() string {
	if sr.IsOpen {
		return "Open"
	}
	return "Closed"
}

// ScanPort attempts to connect to a specified port of a given host, with a specified protocol and timeout.
func ScanPort(protocol, hostname string, port int, timeout time.Duration) ScanResult {
	result := ScanResult{
		Port:     port,
		Protocol: protocol,
		Hostname: hostname,
	}
	address := hostname + ":" + strconv.Itoa(port)
	conn, err := net.DialTimeout(protocol, address, timeout)

	if err != nil {
		result.IsOpen = false
	} else {
		result.IsOpen = true
		conn.Close()
	}

	return result
}

// InitialScan scans a range of ports for a given host or list of hosts, with a specified timeout.
func InitialScan(hosts ...string) {
	var wg sync.WaitGroup

	for _, hostname := range hosts {
		for port := 1; port <= maxPortNumber; port++ {
			wg.Add(1)
			go func(hostname string, port int) {
				defer wg.Done()
				scanResult := ScanPort("tcp", hostname, port, timeout)
				fmt.Print(scanResult.colorizeOutput())
			}(hostname, port)
		}
	}

	wg.Wait()
}

func main() {
	var hostname string

	fmt.Print("Enter the hostname or IP address to scan (leave blank for localhost): ")
	fmt.Scanln(&hostname)

	if hostname == "" {
		hostname = "localhost"
	}

	fmt.Println("Starting port scan...")

	ips, err := net.LookupHost(hostname)
	if err != nil {
		fmt.Printf("Error resolving hostname: %v\n", err)
		return
	}
	if len(ips) > 0 {
		InitialScan(ips[0])
	} else {
		InitialScan(hostname)
	}
}
