package tun

import (
	"context"
	"net/netip"
	"sync"
	"time"

	E "github.com/metacubex/sing/common/exceptions"
)

const (
	natPortRangeStart = 10000
	natPortRangeEnd   = 65535
	natPortRangeSize  = natPortRangeEnd - natPortRangeStart + 1
)

type TCPNat struct {
	timeout         time.Duration
	cleanupInterval time.Duration
	portIndex       uint16
	portAccess      sync.RWMutex
	addrAccess      sync.RWMutex
	addrMap         map[tcpNatKey]uint16
	portMap         map[uint16]*TCPSession
}

type tcpNatKey struct {
	Source      netip.AddrPort
	Destination netip.AddrPort
}

type TCPSession struct {
	sync.Mutex
	Source      netip.AddrPort
	Destination netip.AddrPort
	LastActive  time.Time
	ActivitySeq uint64
}

type TCPSessionSnapshot struct {
	Found       bool
	State       string
	LastActive  time.Time
	Age         time.Duration
	ActivitySeq uint64
}

func NewNat(ctx context.Context, timeout time.Duration) *TCPNat {
	cleanupInterval := timeout / 4
	if cleanupInterval <= 0 || cleanupInterval > 30*time.Second {
		cleanupInterval = 30 * time.Second
	}
	if cleanupInterval < 5*time.Second {
		cleanupInterval = 5 * time.Second
	}
	natMap := &TCPNat{
		timeout:         timeout,
		cleanupInterval: cleanupInterval,
		portIndex:       natPortRangeStart,
		addrMap:         make(map[tcpNatKey]uint16),
		portMap:         make(map[uint16]*TCPSession),
	}
	go natMap.loopCheckTimeout(ctx)
	return natMap
}

func (n *TCPNat) loopCheckTimeout(ctx context.Context) {
	ticker := time.NewTicker(n.cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			n.checkTimeout()
		case <-ctx.Done():
			return
		}
	}
}

func (n *TCPNat) checkTimeout() {
	now := time.Now()
	n.addrAccess.Lock()
	defer n.addrAccess.Unlock()
	n.portAccess.Lock()
	defer n.portAccess.Unlock()
	for natPort, session := range n.portMap {
		session.Lock()
		expired := now.Sub(session.LastActive) > n.timeout
		source := session.Source
		destination := session.Destination
		session.Unlock()
		if !expired {
			continue
		}
		delete(n.portMap, natPort)
		key := tcpNatKey{Source: source, Destination: destination}
		if mappedPort, loaded := n.addrMap[key]; loaded && mappedPort == natPort {
			delete(n.addrMap, key)
		}
	}
}

func (n *TCPNat) LookupBack(port uint16) *TCPSession {
	n.portAccess.RLock()
	session := n.portMap[port]
	n.portAccess.RUnlock()
	if session != nil {
		n.touch(session)
	}
	return session
}

// Lookup returns the NAT port for the flow, allocating a new session when the
// flow is unknown. It returns an error when every port in the range is occupied
// by a live session (allocator exhaustion).
func (n *TCPNat) Lookup(source netip.AddrPort, destination netip.AddrPort) (uint16, error) {
	key := tcpNatKey{Source: source, Destination: destination}
	n.addrAccess.RLock()
	port, loaded := n.addrMap[key]
	n.addrAccess.RUnlock()
	if loaded {
		if session := n.sessionForPort(port); session != nil {
			n.touch(session)
			return port, nil
		}
	}
	n.addrAccess.Lock()
	defer n.addrAccess.Unlock()
	if port, loaded = n.addrMap[key]; loaded {
		if session := n.sessionForPort(port); session != nil {
			n.touch(session)
			return port, nil
		}
	}
	n.portAccess.Lock()
	nextPort, ok := n.allocatePortLocked()
	if ok {
		n.portMap[nextPort] = &TCPSession{
			Source:      source,
			Destination: destination,
			LastActive:  time.Now(),
		}
	}
	n.portAccess.Unlock()
	if !ok {
		return 0, E.New("NAT port space exhausted")
	}
	n.addrMap[key] = nextPort
	return nextPort, nil
}

// allocatePortLocked scans for a port not held by a live session so that a
// wrapped portIndex can never overwrite an active mapping. Caller must hold
// the portAccess write lock.
func (n *TCPNat) allocatePortLocked() (uint16, bool) {
	for i := 0; i < natPortRangeSize; i++ {
		candidate := n.portIndex
		if candidate < natPortRangeStart {
			candidate = natPortRangeStart
		}
		if candidate == natPortRangeEnd {
			n.portIndex = natPortRangeStart
		} else {
			n.portIndex = candidate + 1
		}
		if _, occupied := n.portMap[candidate]; !occupied {
			return candidate, true
		}
	}
	return 0, false
}

func (n *TCPNat) sessionForPort(port uint16) *TCPSession {
	n.portAccess.RLock()
	session := n.portMap[port]
	n.portAccess.RUnlock()
	return session
}

func (n *TCPNat) touch(session *TCPSession) {
	session.Lock()
	session.ActivitySeq++
	if time.Since(session.LastActive) > time.Second {
		session.LastActive = time.Now()
	}
	session.Unlock()
}

func (n *TCPNat) Snapshot(port uint16) TCPSessionSnapshot {
	n.portAccess.RLock()
	session := n.portMap[port]
	n.portAccess.RUnlock()
	if session == nil {
		return TCPSessionSnapshot{State: "unknown"}
	}
	now := time.Now()
	session.Lock()
	defer session.Unlock()
	return TCPSessionSnapshot{
		Found:       true,
		State:       "active",
		LastActive:  session.LastActive,
		Age:         now.Sub(session.LastActive),
		ActivitySeq: session.ActivitySeq,
	}
}

func (n *TCPNat) Stats() (active int) {
	n.portAccess.RLock()
	defer n.portAccess.RUnlock()
	return len(n.portMap)
}

func (n *TCPNat) State(port uint16) string {
	n.portAccess.RLock()
	defer n.portAccess.RUnlock()
	if _, loaded := n.portMap[port]; loaded {
		return "active"
	}
	return "unknown"
}
