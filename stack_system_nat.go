package tun

import (
	"context"
	"net/netip"
	"sync"
	"time"

	E "github.com/metacubex/sing/common/exceptions"
)

type TCPNat struct {
	timeout         time.Duration
	drainTimeout    time.Duration
	cleanupInterval time.Duration
	portIndex       uint16
	portAccess      sync.RWMutex
	addrAccess      sync.RWMutex
	recentAccess    sync.Mutex
	addrMap         map[tcpNatKey]uint16
	portMap         map[uint16]*TCPSession
	recentClosed    map[uint16]time.Time
}

type tcpNatKey struct {
	Source      netip.AddrPort
	Destination netip.AddrPort
}

type TCPSession struct {
	sync.Mutex
	Source            netip.AddrPort
	Destination       netip.AddrPort
	LastActive        time.Time
	ClosingUntil      time.Time
	Closed            bool
	ResponseStarted   bool
	ResponseStartedAt time.Time
	AppRSTIgnoreUntil time.Time
}

func NewNat(ctx context.Context, timeout time.Duration) *TCPNat {
	cleanupInterval := timeout / 4
	if cleanupInterval <= 0 || cleanupInterval > 30*time.Second {
		cleanupInterval = 30 * time.Second
	}
	if cleanupInterval < 5*time.Second {
		cleanupInterval = 5 * time.Second
	}

	drainTimeout := 3 * time.Minute
	if timeout > 0 && timeout < drainTimeout {
		drainTimeout = timeout
	}

	natMap := &TCPNat{
		timeout:         timeout,
		drainTimeout:    drainTimeout,
		cleanupInterval: cleanupInterval,
		portIndex:       10000,
		addrMap:         make(map[tcpNatKey]uint16),
		portMap:         make(map[uint16]*TCPSession),
		recentClosed:    make(map[uint16]time.Time),
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
		expired := false
		if session.Closed {
			expired = !session.ClosingUntil.IsZero() && !now.Before(session.ClosingUntil)
		} else {
			expired = now.Sub(session.LastActive) >= n.timeout
		}
		if expired {
			delete(n.portMap, natPort)
			key := tcpNatKey{Source: session.Source, Destination: session.Destination}
			if mappedPort, loaded := n.addrMap[key]; loaded && mappedPort == natPort {
				delete(n.addrMap, key)
			}
		}
		session.Unlock()
	}
}

func (n *TCPNat) LookupBack(port uint16) *TCPSession {
	n.portAccess.RLock()
	session := n.portMap[port]
	n.portAccess.RUnlock()
	if session != nil && !n.isClosed(session) {
		n.touch(session)
	}
	return session
}

func (n *TCPNat) Find(source netip.AddrPort, destination netip.AddrPort) (uint16, *TCPSession, bool) {
	key := tcpNatKey{
		Source:      source,
		Destination: destination,
	}
	n.addrAccess.RLock()
	port, loaded := n.addrMap[key]
	n.addrAccess.RUnlock()
	if !loaded {
		return 0, nil, false
	}
	n.portAccess.RLock()
	session := n.portMap[port]
	n.portAccess.RUnlock()
	if session != nil {
		n.touch(session)
	}
	return port, session, session != nil
}

func (n *TCPNat) Lookup(source netip.AddrPort, destination netip.AddrPort) (uint16, error) {
	key := tcpNatKey{Source: source, Destination: destination}
	n.addrAccess.RLock()
	port, loaded := n.addrMap[key]
	n.addrAccess.RUnlock()
	if loaded {
		n.refresh(port)
		return port, nil
	}
	n.addrAccess.Lock()
	defer n.addrAccess.Unlock()
	port, loaded = n.addrMap[key]
	if loaded {
		n.refresh(port)
		return port, nil
	}
	n.portAccess.Lock()
	defer n.portAccess.Unlock()
	nextPort, allocated := n.allocatePortLocked()
	if !allocated {
		return 0, E.New("NAT port space exhausted")
	}
	n.portMap[nextPort] = &TCPSession{
		Source:      source,
		Destination: destination,
		LastActive:  time.Now(),
	}
	n.addrMap[key] = nextPort
	return nextPort, nil
}

func (n *TCPNat) refresh(port uint16) {
	n.portAccess.RLock()
	session := n.portMap[port]
	n.portAccess.RUnlock()
	if session != nil {
		n.touch(session)
	}
}

func (n *TCPNat) allocatePortLocked() (uint16, bool) {
	for i := 0; i < 65535-10000+1; i++ {
		nextPort := n.portIndex
		if nextPort == 0 {
			nextPort = 10000
			n.portIndex = 10001
		} else {
			n.portIndex++
		}
		if _, occupied := n.portMap[nextPort]; !occupied {
			return nextPort, true
		}
	}
	return 0, false
}

func (n *TCPNat) DeletePort(port uint16) {
	n.portAccess.RLock()
	session := n.portMap[port]
	n.portAccess.RUnlock()
	if session == nil {
		return
	}

	now := time.Now()
	session.Lock()
	session.Closed = true
	session.LastActive = now
	session.ClosingUntil = now.Add(n.drainTimeout)
	source := session.Source
	destination := session.Destination
	closingUntil := session.ClosingUntil
	session.Unlock()

	n.addrAccess.Lock()
	delete(n.addrMap, tcpNatKey{
		Source:      source,
		Destination: destination,
	})
	n.addrAccess.Unlock()

	n.recentAccess.Lock()
	n.recentClosed[port] = closingUntil.Add(time.Minute)
	n.recentAccess.Unlock()
}

func (n *TCPNat) MarkResponseStarted(port uint16) {
	n.portAccess.RLock()
	session := n.portMap[port]
	n.portAccess.RUnlock()
	if session == nil {
		return
	}
	now := time.Now()
	session.Lock()
	if !session.ResponseStarted {
		session.ResponseStarted = true
		session.ResponseStartedAt = now
	}
	if !session.Closed {
		session.LastActive = now
	}
	session.Unlock()
}

func (n *TCPNat) ShouldSuppressAppRST(port uint16, debounce time.Duration) (bool, time.Time, time.Time, bool, string) {
	n.portAccess.RLock()
	session := n.portMap[port]
	n.portAccess.RUnlock()
	if session == nil {
		return false, time.Time{}, time.Time{}, false, n.State(port)
	}

	now := time.Now()
	session.Lock()
	defer session.Unlock()

	state := "active"
	if session.Closed {
		state = "draining"
	}
	if session.Closed || !session.ResponseStarted {
		return false, session.ResponseStartedAt, session.AppRSTIgnoreUntil, session.ResponseStarted, state
	}
	if now.Before(session.AppRSTIgnoreUntil) {
		return true, session.ResponseStartedAt, session.AppRSTIgnoreUntil, true, state
	}
	session.AppRSTIgnoreUntil = now.Add(debounce)
	return true, session.ResponseStartedAt, session.AppRSTIgnoreUntil, true, state
}

func (n *TCPNat) touch(session *TCPSession) {
	session.Lock()
	if !session.Closed && time.Since(session.LastActive) > time.Second {
		session.LastActive = time.Now()
	}
	session.Unlock()
}

func (n *TCPNat) Stats() (active int, draining int) {
	n.portAccess.RLock()
	defer n.portAccess.RUnlock()
	for _, session := range n.portMap {
		session.Lock()
		if session.Closed {
			draining++
		} else {
			active++
		}
		session.Unlock()
	}
	return
}

func (n *TCPNat) State(port uint16) string {
	n.portAccess.RLock()
	session := n.portMap[port]
	n.portAccess.RUnlock()
	if session != nil {
		session.Lock()
		closed := session.Closed
		session.Unlock()
		if closed {
			return "draining"
		}
		return "active"
	}

	now := time.Now()
	n.recentAccess.Lock()
	defer n.recentAccess.Unlock()
	if until, ok := n.recentClosed[port]; ok {
		if now.Before(until) {
			return "recently_closed"
		}
		delete(n.recentClosed, port)
	}
	return "unknown"
}

func (n *TCPNat) isClosed(session *TCPSession) bool {
	session.Lock()
	defer session.Unlock()
	return session.Closed
}
