package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// MIB_TCPROW_OWNER_PID is a Go representation of the Windows MIB_TCPROW_OWNER_PID struct.
type MIB_TCPROW_OWNER_PID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

// MIB_TCP_STATE_DELETE_TCB is the value to set the state to kill a connection.
const MIB_TCP_STATE_DELETE_TCB = 12

// MIB_TCP_STATE_ESTABLISHED is the value for the established state.
const MIB_TCP_STATE_ESTABLISHED = 5

// connectionTracker holds the first time a connection was seen.
var connectionTracker = make(map[string]time.Time)

// getActiveTCPConnections fetches the current TCP connection table.
func getActiveTCPConnections() (map[string]MIB_TCPROW_OWNER_PID, error) {
	// API from iphlpapi.dll
	iphlpapi := windows.NewLazySystemDLL("iphlpapi.dll")
	getExtendedTcpTable := iphlpapi.NewProc("GetExtendedTcpTable")

	connections := make(map[string]MIB_TCPROW_OWNER_PID)
	var buffer []byte
	var bufSize uint32

	// First call to get the required buffer size
	ret, _, _ := getExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(nil)),
		uintptr(unsafe.Pointer(&bufSize)),
		0, // Sort order
		windows.AF_INET,
		5, // TCP_TABLE_OWNER_PID_ALL
		0,
	)

	if ret != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, fmt.Errorf("GetExtendedTcpTable returned unexpected error: %d", ret)
	}

	buffer = make([]byte, bufSize)

	// Second call to get the actual data
	ret, _, _ = getExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&bufSize)),
		0,
		windows.AF_INET,
		5, // TCP_TABLE_OWNER_PID_ALL
		0,
	)

	if ret != uintptr(windows.NO_ERROR) {
		return nil, fmt.Errorf("GetExtendedTcpTable failed: %d", ret)
	}

	// The first 4 bytes of the buffer are the number of entries
	numEntries := *(*uint32)(unsafe.Pointer(&buffer[0]))
	// The table starts after the count
	table := buffer[4:]

	rowSize := unsafe.Sizeof(MIB_TCPROW_OWNER_PID{})

	for i := uint32(0); i < numEntries; i++ {
		start := i * uint32(rowSize)
		row := *(*MIB_TCPROW_OWNER_PID)(unsafe.Pointer(&table[start]))

		localIP := make(net.IP, 4)
		remoteIP := make(net.IP, 4)
		binary.LittleEndian.PutUint32(localIP, row.LocalAddr)
		binary.LittleEndian.PutUint32(remoteIP, row.RemoteAddr)

		localPort := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&row.LocalPort))[:])
		remotePort := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&row.RemotePort))[:])

		// Create a unique key for the connection
		key := fmt.Sprintf("%s:%d-%s:%d", localIP, localPort, remoteIP, remotePort)
		connections[key] = row
	}

	return connections, nil
}

// killTCPConnection terminates a TCP connection using SetTcpEntry.
func killTCPConnection(row MIB_TCPROW_OWNER_PID) error {
	iphlpapi := windows.NewLazySystemDLL("iphlpapi.dll")
	setTcpEntry := iphlpapi.NewProc("SetTcpEntry")

	// Create the MIB_TCPROW struct required by SetTcpEntry
	type MIB_TCPROW struct {
		State      uint32
		LocalAddr  uint32
		LocalPort  uint32
		RemoteAddr uint32
		RemotePort uint32
	}

	killRow := MIB_TCPROW{
		State:      MIB_TCP_STATE_DELETE_TCB,
		LocalAddr:  row.LocalAddr,
		LocalPort:  row.LocalPort,
		RemoteAddr: row.RemoteAddr,
		RemotePort: row.RemotePort,
	}

	ret, _, err := setTcpEntry.Call(uintptr(unsafe.Pointer(&killRow)))
	if ret != uintptr(windows.NO_ERROR) {
		return fmt.Errorf("SetTcpEntry failed with code %d: %v", ret, err)
	}

	return nil
}

func main() {
	timeout := flag.Duration("timeout", 5*time.Minute, "Timeout duration for TCP connections (e.g., '10s', '5m', '1h').")
	interval := flag.Duration("interval", 10*time.Second, "Interval between connection checks.")
	flag.Parse()

	log.Printf("Starting TCP connection killer. Timeout: %s, Check Interval: %s", *timeout, *interval)
	log.Println("Run with administrator privileges. Press Ctrl+C to exit.")

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			checkAndKillConnections(*timeout)
		case <-sigChan:
			log.Println("Shutting down...")
			return
		}
	}
}

func checkAndKillConnections(timeout time.Duration) {
	currentConnections, err := getActiveTCPConnections()
	if err != nil {
		log.Printf("Error getting TCP connections: %v", err)
		return
	}

	now := time.Now()

	// Set to keep track of connections seen in this scan
	seenKeys := make(map[string]bool)

	for key, row := range currentConnections {
		seenKeys[key] = true
		if _, exists := connectionTracker[key]; !exists {
			// New connection found, start tracking it
			connectionTracker[key] = now
			log.Printf("Tracking new connection: %s (PID: %d)", key, row.OwningPid)
		} else {
			// Existing connection, check its age
			firstSeenTime := connectionTracker[key]
			age := now.Sub(firstSeenTime)

			if age > timeout {
				// Only kill connections that are in the established state.
				if row.State == MIB_TCP_STATE_ESTABLISHED {
					log.Printf("Killing established connection > %s old: %s (PID: %d, Age: %s)", timeout, key, row.OwningPid, age.Truncate(time.Second))
					if err := killTCPConnection(row); err != nil {
						log.Printf("Failed to kill connection %s: %v", key, err)
					}
					// Remove from tracker after killing
					delete(connectionTracker, key)
				}
			}
		}
	}

	// Clean up tracker: remove connections that have closed naturally
	for key := range connectionTracker {
		if !seenKeys[key] {
			log.Printf("Connection closed naturally: %s", key)
			delete(connectionTracker, key)
		}
	}
}
