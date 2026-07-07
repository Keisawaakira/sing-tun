package tun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	tcpip "github.com/metacubex/sing-tun/internal/gtcpip"
	"github.com/metacubex/sing-tun/internal/gtcpip/checksum"
	"github.com/metacubex/sing-tun/internal/gtcpip/header"
	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/control"
	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

var ErrIncludeAllNetworks = E.New("`system` and `mixed` stack are not available when `includeAllNetworks` is enabled. See https://github.com/SagerNet/sing-tun/issues/25")

type System struct {
	ctx                  context.Context
	tun                  Tun
	tunName              string
	mtu                  int
	handler              Handler
	logger               logger.Logger
	inet4Prefixes        []netip.Prefix
	inet6Prefixes        []netip.Prefix
	inet4Address         netip.Addr
	inet4NextAddress     netip.Addr
	inet6Address         netip.Addr
	inet6NextAddress     netip.Addr
	broadcastAddr        netip.Addr
	inet4LoopbackAddress []netip.Addr
	inet6LoopbackAddress []netip.Addr
	udpTimeout           time.Duration
	icmpTimeout          time.Duration
	tcpListener          net.Listener
	tcpListener6         net.Listener
	tcpPort              uint16
	tcpPort6             uint16
	tcpNat4              *TCPNat
	tcpNat6              *TCPNat
	directNat            *DirectRouteMapping
	bindInterface        bool
	interfaceFinder      control.InterfaceFinder
	enforceBind          bool
	frontHeadroom        int
	txChecksumOffload    bool
	recvMsgX             bool

	lookupBackMisses      atomic.Uint64
	lastLookupBackMissLog atomic.Int64
	natExhaustedDrops     atomic.Uint64
	lastNatExhaustedLog   atomic.Int64
}

type Session struct {
	SourceAddress      netip.Addr
	DestinationAddress netip.Addr
	SourcePort         uint16
	DestinationPort    uint16
}

type responseTrackingTCPConn struct {
	net.Conn
	startedAt     time.Time
	localAddr     string
	remoteAddr    string
	readBytes     int64
	writeBytes    int64
	lastReadNano  int64
	lastWriteNano int64
	errMu         sync.Mutex
	lastReadErr   string
	lastWriteErr  string
}

type responseTrackingSnapshot struct {
	startedAt    time.Time
	duration     time.Duration
	localAddr    string
	remoteAddr   string
	readBytes    int64
	writeBytes   int64
	lastReadAt   time.Time
	lastWriteAt  time.Time
	lastReadErr  string
	lastWriteErr string
}

func newResponseTrackingTCPConn(conn net.Conn) *responseTrackingTCPConn {
	return &responseTrackingTCPConn{
		Conn:       conn,
		startedAt:  time.Now(),
		localAddr:  tcpBridgeAddrString(conn.LocalAddr()),
		remoteAddr: tcpBridgeAddrString(conn.RemoteAddr()),
	}
}

func (c *responseTrackingTCPConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		atomic.AddInt64(&c.readBytes, int64(n))
		atomic.StoreInt64(&c.lastReadNano, time.Now().UnixNano())
	}
	if err != nil {
		c.setLastReadErr(err)
	}
	return n, err
}

func (c *responseTrackingTCPConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		atomic.AddInt64(&c.writeBytes, int64(n))
		atomic.StoreInt64(&c.lastWriteNano, time.Now().UnixNano())
	}
	if err != nil {
		c.setLastWriteErr(err)
	}
	return n, err
}

func (c *responseTrackingTCPConn) CloseWrite() error {
	if writeCloser, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return writeCloser.CloseWrite()
	}
	return c.Conn.Close()
}

func (c *responseTrackingTCPConn) CloseRead() error {
	if readCloser, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return readCloser.CloseRead()
	}
	return c.Conn.Close()
}

func (c *responseTrackingTCPConn) Snapshot() responseTrackingSnapshot {
	lastReadNano := atomic.LoadInt64(&c.lastReadNano)
	lastWriteNano := atomic.LoadInt64(&c.lastWriteNano)
	c.errMu.Lock()
	lastReadErr := c.lastReadErr
	lastWriteErr := c.lastWriteErr
	c.errMu.Unlock()
	return responseTrackingSnapshot{
		startedAt:    c.startedAt,
		duration:     time.Since(c.startedAt),
		localAddr:    c.localAddr,
		remoteAddr:   c.remoteAddr,
		readBytes:    atomic.LoadInt64(&c.readBytes),
		writeBytes:   atomic.LoadInt64(&c.writeBytes),
		lastReadAt:   tcpBridgeTimeFromUnixNano(lastReadNano),
		lastWriteAt:  tcpBridgeTimeFromUnixNano(lastWriteNano),
		lastReadErr:  lastReadErr,
		lastWriteErr: lastWriteErr,
	}
}

func (c *responseTrackingTCPConn) setLastReadErr(err error) {
	c.errMu.Lock()
	c.lastReadErr = err.Error()
	c.errMu.Unlock()
}

func (c *responseTrackingTCPConn) setLastWriteErr(err error) {
	c.errMu.Lock()
	c.lastWriteErr = err.Error()
	c.errMu.Unlock()
}

func NewSystem(options StackOptions) (Stack, error) {
	stack := &System{
		ctx:                  options.Context,
		tun:                  options.Tun,
		tunName:              options.TunOptions.Name,
		mtu:                  int(options.TunOptions.MTU),
		inet4LoopbackAddress: options.TunOptions.Inet4LoopbackAddress,
		inet6LoopbackAddress: options.TunOptions.Inet6LoopbackAddress,
		udpTimeout:           options.UDPTimeout,
		icmpTimeout:          options.ICMPTimeout,
		handler:              options.Handler,
		logger:               options.Logger,
		inet4Prefixes:        options.TunOptions.Inet4Address,
		inet6Prefixes:        options.TunOptions.Inet6Address,
		broadcastAddr:        BroadcastAddr(options.TunOptions.Inet4Address),
		bindInterface:        options.ForwarderBindInterface,
		interfaceFinder:      options.InterfaceFinder,
		recvMsgX:             options.TunOptions.EXP_RecvMsgX,
		enforceBind:          options.EnforceBindInterface,
	}
	if len(options.TunOptions.Inet4Address) > 0 {
		if !HasNextAddress(options.TunOptions.Inet4Address[0], 1) {
			return nil, E.New("need one more IPv4 address in first prefix for system stack")
		}
		stack.inet4Address = options.TunOptions.Inet4Address[0].Addr()
		stack.inet4NextAddress = stack.inet4Address.Next()
	}
	if len(options.TunOptions.Inet6Address) > 0 {
		if !HasNextAddress(options.TunOptions.Inet6Address[0], 1) {
			return nil, E.New("need one more IPv6 address in first prefix for system stack")
		}
		stack.inet6Address = options.TunOptions.Inet6Address[0].Addr()
		stack.inet6NextAddress = stack.inet6Address.Next()
	}
	if !stack.inet4NextAddress.IsValid() && !stack.inet6NextAddress.IsValid() {
		return nil, E.New("missing interface address")
	}
	return stack, nil
}

func (s *System) Close() error {
	return common.Close(
		s.tcpListener,
		s.tcpListener6,
	)
}

func (s *System) Start() error {
	err := s.start()
	if err != nil {
		return err
	}
	go s.tunLoop()
	return nil
}

func (s *System) start() error {
	_ = fixWindowsFirewall()
	var listener net.ListenConfig
	if s.bindInterface || s.enforceBind {
		listener.Control = control.Append(listener.Control, func(network, address string, conn syscall.RawConn) error {
			bindErr := control.BindToInterface0(s.interfaceFinder, conn, network, address, s.tunName, -1, true)
			if bindErr != nil {
				s.logger.Warn("bind forwarder to interface: ", bindErr)
			}
			if s.enforceBind {
				return bindErr
			}
			return nil
		})
	}
	var tcpListener net.Listener
	var err error
	if s.inet4NextAddress.IsValid() {
		address := net.JoinHostPort(s.inet4Address.String(), "0")
		if s.enforceBind {
			address = "0.0.0.0:0"
		}
		for i := 0; i < 3; i++ {
			tcpListener, err = listener.Listen(s.ctx, "tcp4", address)
			if !retryableListenError(err) {
				break
			}
			time.Sleep(time.Second)
		}
		if err != nil {
			return err
		}
		s.tcpListener = tcpListener
		s.tcpPort = M.SocksaddrFromNet(tcpListener.Addr()).Port
		s.tcpNat4 = NewNat(s.ctx, s.udpTimeout)
		go s.acceptLoop(tcpListener, s.tcpNat4)
	}
	if s.inet6NextAddress.IsValid() {
		address := net.JoinHostPort(s.inet6Address.String(), "0")
		if s.enforceBind {
			address = "[:]:0"
		}
		for i := 0; i < 3; i++ {
			tcpListener, err = listener.Listen(s.ctx, "tcp6", address)
			if !retryableListenError(err) {
				break
			}
			time.Sleep(time.Second)
		}
		if err != nil {
			return err
		}
		s.tcpListener6 = tcpListener
		s.tcpPort6 = M.SocksaddrFromNet(tcpListener.Addr()).Port
		s.tcpNat6 = NewNat(s.ctx, s.udpTimeout)
		go s.acceptLoop(tcpListener, s.tcpNat6)
	}
	s.directNat = NewDirectRouteMapping(s.icmpTimeout)
	return nil
}

func (s *System) tunLoop() {
	if winTun, isWinTun := s.tun.(WinTun); isWinTun {
		s.wintunLoop(winTun)
		return
	}
	if linuxTUN, isLinuxTUN := s.tun.(LinuxTUN); isLinuxTUN {
		s.frontHeadroom = linuxTUN.FrontHeadroom()
		s.txChecksumOffload = linuxTUN.TXChecksumOffload()
		batchSize := linuxTUN.BatchSize()
		if batchSize > 1 {
			s.batchLoopLinux(linuxTUN, batchSize)
			return
		}
	}
	if darwinTUN, isDarwinTUN := s.tun.(DarwinTUN); isDarwinTUN && s.recvMsgX {
		s.batchLoopDarwin(darwinTUN)
		return
	}
	packetBuffer := make([]byte, s.mtu+PacketOffset)
	for {
		n, err := s.tun.Read(packetBuffer)
		if err != nil {
			if E.IsClosed(err) {
				return
			}
			s.logger.Error(E.Cause(err, "read packet"))
		}
		if n < header.IPv4MinimumSize {
			continue
		}
		rawPacket := packetBuffer[:n]
		packet := packetBuffer[PacketOffset:n]
		if s.processPacket(packet) {
			_, err = s.tun.Write(rawPacket)
			if err != nil {
				s.logger.Trace(E.Cause(err, "write packet"))
			}
		}
	}
}

func (s *System) wintunLoop(winTun WinTun) {
	batchTun, _ := winTun.(WinTunBatch)
	for {
		err := winTun.ReadFunc(func(packet []byte) {
			if len(packet) < header.IPv4MinimumSize {
				return
			}
			if s.processPacket(packet) {
				_, werr := winTun.Write(packet)
				if werr != nil {
					s.logger.Trace(E.Cause(werr, "write packet"))
				}
			}
		})
		if err != nil {
			if !E.IsClosed(err) {
				s.logger.Error(E.Cause(err, "wintun read loop exited"))
			}
			return
		}
		if batchTun == nil {
			continue
		}
		for {
			packet, release, ok, err := batchTun.TryReadPacket()
			if err != nil {
				if !E.IsClosed(err) {
					s.logger.Error(E.Cause(err, "wintun batch read loop exited"))
				}
				return
			}
			if !ok {
				break
			}
			if len(packet) < header.IPv4MinimumSize {
				release()
				continue
			}
			if s.processPacket(packet) {
				_, err = winTun.Write(packet)
				if err != nil {
					s.logger.Trace(E.Cause(err, "write packet"))
				}
			}
			release()
		}
	}
}

func (s *System) batchLoopLinux(linuxTUN LinuxTUN, batchSize int) {
	packetBuffers := make([][]byte, batchSize)
	writeBuffers := make([][]byte, 0, batchSize)
	packetSizes := make([]int, batchSize)
	for i := range packetBuffers {
		packetBuffers[i] = make([]byte, s.mtu+s.frontHeadroom)
	}
	for {
		n, err := linuxTUN.BatchRead(packetBuffers, s.frontHeadroom, packetSizes)
		if err != nil {
			if E.IsClosed(err) {
				return
			}
			s.logger.Error(E.Cause(err, "batch read packet"))
		}
		if n == 0 {
			continue
		}
		for i := 0; i < n; i++ {
			packetSize := packetSizes[i]
			if packetSize < header.IPv4MinimumSize {
				continue
			}
			packetBuffer := packetBuffers[i]
			packet := packetBuffer[s.frontHeadroom : s.frontHeadroom+packetSize]
			if s.processPacket(packet) {
				writeBuffers = append(writeBuffers, packetBuffer[:s.frontHeadroom+packetSize])
			}
		}
		if len(writeBuffers) > 0 {
			_, err = linuxTUN.BatchWrite(writeBuffers, s.frontHeadroom)
			if err != nil {
				s.logger.Trace(E.Cause(err, "batch write packet"))
			}
			writeBuffers = writeBuffers[:0]
		}
	}
}

func (s *System) batchLoopDarwin(darwinTUN DarwinTUN) {
	var writeBuffers []*buf.Buffer
	for {
		buffers, err := darwinTUN.BatchRead()
		if err != nil {
			if E.IsClosed(err) {
				return
			}
			s.logger.Error(E.Cause(err, "batch read packet"))
		}
		if len(buffers) == 0 {
			continue
		}
		writeBuffers = writeBuffers[:0]
		for _, buffer := range buffers {
			packetSize := buffer.Len()
			if packetSize < header.IPv4MinimumSize {
				buffer.Release()
				continue
			}
			if s.processPacket(buffer.Bytes()) {
				writeBuffers = append(writeBuffers, buffer)
			} else {
				buffer.Release()
			}
		}
		if len(writeBuffers) > 0 {
			err = darwinTUN.BatchWrite(writeBuffers)
			if err != nil {
				s.logger.Trace(E.Cause(err, "batch write packet"))
			}
			buf.ReleaseMulti(writeBuffers)
		}
	}
}

func (s *System) processPacket(packet []byte) bool {
	var (
		writeBack bool
		err       error
	)
	switch ipVersion := header.IPVersion(packet); ipVersion {
	case header.IPv4Version:
		writeBack, err = s.processIPv4(packet)
	case header.IPv6Version:
		writeBack, err = s.processIPv6(packet)
	default:
		err = E.New("ip: unknown version: ", ipVersion)
	}
	if err != nil {
		s.logger.Trace(err)
		return false
	}
	return writeBack
}

func (s *System) acceptLoop(listener net.Listener, tcpNat *TCPNat) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		connPort := M.SocksaddrFromNet(conn.RemoteAddr()).Port
		session := tcpNat.LookupBack(connPort)
		if session == nil {
			s.logTCPBridgeAcceptMissing(tcpNat, connPort, conn)
			_ = conn.Close()
			continue
		}
		go func(conn net.Conn, connPort uint16, source netip.AddrPort, destination netip.AddrPort) {
			trackedConn := newResponseTrackingTCPConn(conn)
			metadata := M.Metadata{
				Source:      M.SocksaddrFromNetIP(source),
				Destination: M.SocksaddrFromNetIP(destination),
			}
			handlerErr := s.handler.NewConnection(s.ctx, trackedConn, metadata)
			connSnapshot := trackedConn.Snapshot()
			natSnapshot := tcpNat.Snapshot(connPort)
			s.logTCPBridgeDone(tcpNat, connPort, source, destination, connSnapshot, natSnapshot, handlerErr)
			// Close with RST (upstream semantics): the NAT session stays alive
			// until idle timeout, so the RST is rewritten back to the app and
			// tears the app-side connection down immediately instead of
			// leaving it to drain against a dead socket.
			if tcpConn, isTCPConn := conn.(*net.TCPConn); isTCPConn {
				_ = tcpConn.SetLinger(0)
			}
			_ = trackedConn.Close()
		}(conn, connPort, session.Source, session.Destination)
	}
}

func (s *System) logTCPBridgeAcceptMissing(tcpNat *TCPNat, connPort uint16, conn net.Conn) {
	active := 0
	state := "unknown"
	if tcpNat != nil {
		active = tcpNat.Stats()
		state = tcpNat.State(connPort)
	}
	s.logger.Warn(
		"[TCPLocal] bridge-accept-missing nat_port=", connPort,
		" state=", state,
		" active=", active,
		" local=", tcpBridgeAddrString(conn.LocalAddr()),
		" remote=", tcpBridgeAddrString(conn.RemoteAddr()),
	)
}

func (s *System) logTCPBridgeDone(tcpNat *TCPNat, natPort uint16, source netip.AddrPort, destination netip.AddrPort, connSnapshot responseTrackingSnapshot, natSnapshot TCPSessionSnapshot, handlerErr error) {
	if !shouldLogTCPBridgeDone(connSnapshot, handlerErr) {
		return
	}
	active := 0
	if tcpNat != nil {
		active = tcpNat.Stats()
	}
	s.logger.Warn(
		"[TCPLocal] bridge-done nat_port=", natPort,
		" state=", natSnapshot.State,
		" duration=", connSnapshot.duration.Round(time.Millisecond),
		" read_bytes=", connSnapshot.readBytes,
		" write_bytes=", connSnapshot.writeBytes,
		" last_read_at=", tcpBridgeTimeString(connSnapshot.lastReadAt),
		" last_read_since_start=", tcpBridgeSinceStart(connSnapshot.startedAt, connSnapshot.lastReadAt).Round(time.Millisecond),
		" last_write_at=", tcpBridgeTimeString(connSnapshot.lastWriteAt),
		" last_write_since_start=", tcpBridgeSinceStart(connSnapshot.startedAt, connSnapshot.lastWriteAt).Round(time.Millisecond),
		" read_err=", connSnapshot.lastReadErr,
		" write_err=", connSnapshot.lastWriteErr,
		" handler_err=", handlerErr,
		" last_active=", natSnapshot.LastActive,
		" age=", natSnapshot.Age.Round(time.Millisecond),
		" activity_seq=", natSnapshot.ActivitySeq,
		" active=", active,
		" src=", source,
		" dst=", destination,
		" local=", connSnapshot.localAddr,
		" remote=", connSnapshot.remoteAddr,
	)
}

func shouldLogTCPBridgeDone(connSnapshot responseTrackingSnapshot, handlerErr error) bool {
	if handlerErr != nil {
		return true
	}
	return tcpBridgeHardError(connSnapshot.lastReadErr) || tcpBridgeHardError(connSnapshot.lastWriteErr)
}

func tcpBridgeHardError(message string) bool {
	if message == "" {
		return false
	}
	message = strings.ToLower(message)
	if message == "eof" || strings.Contains(message, "use of closed network connection") || strings.Contains(message, "closed pipe") {
		return false
	}
	return strings.Contains(message, "connection attempt failed") ||
		strings.Contains(message, "forcibly closed") ||
		strings.Contains(message, "connection reset") ||
		strings.Contains(message, "i/o timeout") ||
		strings.Contains(message, "broken pipe") ||
		strings.Contains(message, "failed")
}

func tcpBridgeTimeFromUnixNano(nano int64) time.Time {
	if nano == 0 {
		return time.Time{}
	}
	return time.Unix(0, nano)
}

func tcpBridgeTimeString(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339Nano)
}

func tcpBridgeSinceStart(startedAt time.Time, at time.Time) time.Duration {
	if startedAt.IsZero() || at.IsZero() {
		return 0
	}
	return at.Sub(startedAt)
}

func tcpBridgeAddrString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

func (s *System) processIPv4(ipHdr header.IPv4) (writeBack bool, err error) {
	destination := ipHdr.DestinationAddr()
	if destination == s.broadcastAddr || !destination.IsGlobalUnicast() {
		return
	}
	writeBack = true
	switch ipHdr.TransportProtocol() {
	case header.TCPProtocolNumber:
		writeBack, err = s.processIPv4TCP(ipHdr, ipHdr.Payload())
	case header.UDPProtocolNumber:
		writeBack = false
		err = s.processIPv4UDP(ipHdr, ipHdr.Payload())
	case header.ICMPv4ProtocolNumber:
		writeBack, err = s.processIPv4ICMP(ipHdr, ipHdr.Payload())
	}
	if err != nil {
		writeBack = false
	}
	return
}

func (s *System) processIPv6(ipHdr header.IPv6) (writeBack bool, err error) {
	if !ipHdr.DestinationAddr().IsGlobalUnicast() {
		return
	}
	writeBack = true
	switch ipHdr.TransportProtocol() {
	case header.TCPProtocolNumber:
		writeBack, err = s.processIPv6TCP(ipHdr, ipHdr.Payload())
	case header.UDPProtocolNumber:
		writeBack = false
		err = s.processIPv6UDP(ipHdr, ipHdr.Payload())
	case header.ICMPv6ProtocolNumber:
		writeBack, err = s.processIPv6ICMP(ipHdr, ipHdr.Payload())
	}
	if err != nil {
		writeBack = false
	}
	return
}

func transportAddress(addr netip.Addr) tcpip.Address {
	if addr.Is6() {
		return tcpip.AddrFrom16(addr.As16())
	}
	return tcpip.AddrFrom4(addr.As4())
}

func (s *System) rewriteIPv4TCPPacket(ipHdr header.IPv4, tcpHdr header.TCP, source, destination netip.AddrPort) {
	if s.txChecksumOffload {
		ipHdr.SetSourceAddr(source.Addr())
		tcpHdr.SetSourcePort(source.Port())
		ipHdr.SetDestinationAddr(destination.Addr())
		tcpHdr.SetDestinationPort(destination.Port())
		tcpHdr.SetChecksum(0)
		ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
		return
	}

	sourceAddr := transportAddress(source.Addr())
	tcpHdr.UpdateChecksumPseudoHeaderAddress(ipHdr.SourceAddress(), sourceAddr, true)
	tcpHdr.SetSourcePortWithChecksumUpdate(source.Port())
	ipHdr.SetSourceAddressWithChecksumUpdate(sourceAddr)

	destinationAddr := transportAddress(destination.Addr())
	tcpHdr.UpdateChecksumPseudoHeaderAddress(ipHdr.DestinationAddress(), destinationAddr, true)
	tcpHdr.SetDestinationPortWithChecksumUpdate(destination.Port())
	ipHdr.SetDestinationAddressWithChecksumUpdate(destinationAddr)
}

func (s *System) rewriteIPv6TCPPacket(ipHdr header.IPv6, tcpHdr header.TCP, source, destination netip.AddrPort) {
	if s.txChecksumOffload {
		ipHdr.SetSourceAddr(source.Addr())
		tcpHdr.SetSourcePort(source.Port())
		ipHdr.SetDestinationAddr(destination.Addr())
		tcpHdr.SetDestinationPort(destination.Port())
		tcpHdr.SetChecksum(0)
		return
	}

	sourceAddr := transportAddress(source.Addr())
	tcpHdr.UpdateChecksumPseudoHeaderAddress(ipHdr.SourceAddress(), sourceAddr, true)
	tcpHdr.SetSourcePortWithChecksumUpdate(source.Port())
	ipHdr.SetSourceAddress(sourceAddr)

	destinationAddr := transportAddress(destination.Addr())
	tcpHdr.UpdateChecksumPseudoHeaderAddress(ipHdr.DestinationAddress(), destinationAddr, true)
	tcpHdr.SetDestinationPortWithChecksumUpdate(destination.Port())
	ipHdr.SetDestinationAddress(destinationAddr)
}

func (s *System) processIPv4TCP(ipHdr header.IPv4, tcpHdr header.TCP) (bool, error) {
	if s.tcpNat4 == nil {
		return false, nil
	}
	source := netip.AddrPortFrom(ipHdr.SourceAddr(), tcpHdr.SourcePort())
	destination := netip.AddrPortFrom(ipHdr.DestinationAddr(), tcpHdr.DestinationPort())
	if !destination.Addr().IsGlobalUnicast() {
		return false, nil
	} else if source.Addr() == s.inet4Address && source.Port() == s.tcpPort {
		session := s.tcpNat4.LookupBack(destination.Port())
		if session == nil {
			s.logLookupBackMiss(s.tcpNat4, "ipv4", destination.Port())
			return false, nil
		}
		source = session.Destination
		destination = session.Source
	} else {
		var loopback bool
		for _, inet4LoopbackAddress := range s.inet4LoopbackAddress {
			if destination.Addr() == inet4LoopbackAddress {
				destination = netip.AddrPortFrom(ipHdr.SourceAddr(), tcpHdr.DestinationPort())
				source = netip.AddrPortFrom(inet4LoopbackAddress, tcpHdr.SourcePort())
				loopback = true
				break
			}
		}
		if !loopback {
			natPort, err := s.tcpNat4.Lookup(source, destination)
			if err != nil {
				s.logNatPortExhausted(s.tcpNat4, "ipv4", source, destination)
				return false, s.resetIPv4TCP(ipHdr, tcpHdr)
			}
			source = netip.AddrPortFrom(s.inet4NextAddress, natPort)
			destination = netip.AddrPortFrom(s.inet4Address, s.tcpPort)
		}
	}
	s.rewriteIPv4TCPPacket(ipHdr, tcpHdr, source, destination)
	return true, nil
}

func (s *System) resetIPv4TCP(origIPHdr header.IPv4, origTCPHdr header.TCP) error {
	frontHeadroom := s.frontHeadroom + PacketOffset
	newPacket := buf.NewSize(frontHeadroom + header.IPv4MinimumSize + header.TCPMinimumSize)
	defer newPacket.Release()
	newPacket.Resize(frontHeadroom, header.IPv4MinimumSize+header.TCPMinimumSize)
	ipHdr := header.IPv4(newPacket.Bytes())
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(newPacket.Len()),
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     origIPHdr.DestinationAddr(),
		DstAddr:     origIPHdr.SourceAddr(),
	})
	tcpHdr := header.TCP(ipHdr.Payload())
	fields := header.TCPFields{
		SrcPort:    origTCPHdr.DestinationPort(),
		DstPort:    origTCPHdr.SourcePort(),
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagRst,
	}
	if origTCPHdr.Flags()&header.TCPFlagAck != 0 {
		fields.SeqNum = origTCPHdr.AckNumber()
	} else {
		fields.Flags |= header.TCPFlagAck
		ackNum := origTCPHdr.SequenceNumber() + uint32(len(origTCPHdr.Payload()))
		if origTCPHdr.Flags()&header.TCPFlagSyn != 0 {
			ackNum++
		}
		if origTCPHdr.Flags()&header.TCPFlagFin != 0 {
			ackNum++
		}
		fields.AckNum = ackNum
	}
	tcpHdr.Encode(&fields)
	if !s.txChecksumOffload {
		tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), header.TCPMinimumSize)))
	}
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	if PacketOffset > 0 {
		PacketFillHeader(newPacket.ExtendHeader(PacketOffset), header.IPv4Version)
	} else {
		newPacket.Advance(-s.frontHeadroom)
	}
	return common.Error(s.tun.Write(newPacket.Bytes()))
}

func (s *System) processIPv6TCP(ipHdr header.IPv6, tcpHdr header.TCP) (bool, error) {
	if s.tcpNat6 == nil {
		return false, nil
	}
	source := netip.AddrPortFrom(ipHdr.SourceAddr(), tcpHdr.SourcePort())
	destination := netip.AddrPortFrom(ipHdr.DestinationAddr(), tcpHdr.DestinationPort())
	if !destination.Addr().IsGlobalUnicast() {
		return false, nil
	} else if source.Addr() == s.inet6Address && source.Port() == s.tcpPort6 {
		session := s.tcpNat6.LookupBack(destination.Port())
		if session == nil {
			s.logLookupBackMiss(s.tcpNat6, "ipv6", destination.Port())
			return false, nil
		}
		source = session.Destination
		destination = session.Source
	} else {
		var loopback bool
		for _, inet6LoopbackAddress := range s.inet6LoopbackAddress {
			if destination.Addr() == inet6LoopbackAddress {
				destination = netip.AddrPortFrom(ipHdr.SourceAddr(), tcpHdr.DestinationPort())
				source = netip.AddrPortFrom(inet6LoopbackAddress, tcpHdr.SourcePort())
				loopback = true
				break
			}
		}
		if !loopback {
			natPort, err := s.tcpNat6.Lookup(source, destination)
			if err != nil {
				s.logNatPortExhausted(s.tcpNat6, "ipv6", source, destination)
				return false, s.resetIPv6TCP(ipHdr, tcpHdr)
			}
			source = netip.AddrPortFrom(s.inet6NextAddress, natPort)
			destination = netip.AddrPortFrom(s.inet6Address, s.tcpPort6)
		}
	}
	s.rewriteIPv6TCPPacket(ipHdr, tcpHdr, source, destination)
	return true, nil
}

// logLookupBackMiss records reply-direction packets dropped because the NAT
// no longer knows the port. Every dropped packet counts; log lines are
// rate-limited to one per second to survive storms.
func (s *System) logLookupBackMiss(tcpNat *TCPNat, family string, natPort uint16) {
	misses := s.lookupBackMisses.Add(1)
	now := time.Now().UnixNano()
	last := s.lastLookupBackMissLog.Load()
	if now-last < int64(time.Second) || !s.lastLookupBackMissLog.CompareAndSwap(last, now) {
		return
	}
	active := 0
	if tcpNat != nil {
		active = tcpNat.Stats()
	}
	s.logger.Warn(
		"[TCPLocal] bridge-lookup-miss family=", family,
		" nat_port=", natPort,
		" total_misses=", misses,
		" active=", active,
	)
}

// logNatPortExhausted records forward-direction packets rejected because every
// NAT port is occupied by a live session. This should never happen in normal
// operation; if it fires, sessions are leaking or genuinely exceed ~55k.
func (s *System) logNatPortExhausted(tcpNat *TCPNat, family string, source netip.AddrPort, destination netip.AddrPort) {
	drops := s.natExhaustedDrops.Add(1)
	now := time.Now().UnixNano()
	last := s.lastNatExhaustedLog.Load()
	if now-last < int64(time.Second) || !s.lastNatExhaustedLog.CompareAndSwap(last, now) {
		return
	}
	active := 0
	if tcpNat != nil {
		active = tcpNat.Stats()
	}
	s.logger.Error(
		"[TCPLocal] nat-port-exhausted family=", family,
		" total_drops=", drops,
		" active=", active,
		" src=", source,
		" dst=", destination,
	)
}

func (s *System) resetIPv6TCP(origIPHdr header.IPv6, origTCPHdr header.TCP) error {
	frontHeadroom := s.frontHeadroom + PacketOffset
	newPacket := buf.NewSize(frontHeadroom + header.IPv6MinimumSize + header.TCPMinimumSize)
	defer newPacket.Release()
	newPacket.Resize(frontHeadroom, header.IPv6MinimumSize+header.TCPMinimumSize)
	ipHdr := header.IPv6(newPacket.Bytes())
	ipHdr.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.TCPMinimumSize),
		TransportProtocol: header.TCPProtocolNumber,
		SrcAddr:           origIPHdr.DestinationAddr(),
		DstAddr:           origIPHdr.SourceAddr(),
	})
	tcpHdr := header.TCP(ipHdr.Payload())
	fields := header.TCPFields{
		SrcPort:    origTCPHdr.DestinationPort(),
		DstPort:    origTCPHdr.SourcePort(),
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagRst,
	}
	if origTCPHdr.Flags()&header.TCPFlagAck != 0 {
		fields.SeqNum = origTCPHdr.AckNumber()
	} else {
		fields.Flags |= header.TCPFlagAck
		ackNum := origTCPHdr.SequenceNumber() + uint32(len(origTCPHdr.Payload()))
		if origTCPHdr.Flags()&header.TCPFlagSyn != 0 {
			ackNum++
		}
		if origTCPHdr.Flags()&header.TCPFlagFin != 0 {
			ackNum++
		}
		fields.AckNum = ackNum
	}
	tcpHdr.Encode(&fields)
	if !s.txChecksumOffload {
		tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), header.TCPMinimumSize)))
	}
	if PacketOffset > 0 {
		PacketFillHeader(newPacket.ExtendHeader(PacketOffset), header.IPv6Version)
	} else {
		newPacket.Advance(-s.frontHeadroom)
	}
	return common.Error(s.tun.Write(newPacket.Bytes()))
}

func (s *System) processIPv4UDP(ipHdr header.IPv4, udpHdr header.UDP) error {
	if ipHdr.Flags()&header.IPv4FlagMoreFragments != 0 {
		return E.New("ipv4: fragment dropped")
	}
	if ipHdr.FragmentOffset() != 0 {
		return E.New("ipv4: udp: fragment dropped")
	}
	source := netip.AddrPortFrom(ipHdr.SourceAddr(), udpHdr.SourcePort())
	destination := netip.AddrPortFrom(ipHdr.DestinationAddr(), udpHdr.DestinationPort())
	if !destination.Addr().IsGlobalUnicast() {
		return nil
	}
	data := buf.As(udpHdr.Payload())
	if data.Len() == 0 {
		return nil
	}
	metadata := M.Metadata{
		Source:      M.SocksaddrFromNetIP(source),
		Destination: M.SocksaddrFromNetIP(destination),
	}
	s.handler.NewPacket(s.ctx, source, data.ToOwned(), metadata, func(natConn N.PacketConn) N.PacketWriter {
		headerLen := ipHdr.HeaderLength() + header.UDPMinimumSize
		headerCopy := make([]byte, headerLen)
		copy(headerCopy, ipHdr[:headerLen])
		return &systemUDPPacketWriter4{
			s.tun,
			s.frontHeadroom + PacketOffset,
			headerCopy,
			source,
			s.txChecksumOffload,
		}
	})
	return nil
}

func (s *System) processIPv6UDP(ipHdr header.IPv6, udpHdr header.UDP) error {
	source := netip.AddrPortFrom(ipHdr.SourceAddr(), udpHdr.SourcePort())
	destination := netip.AddrPortFrom(ipHdr.DestinationAddr(), udpHdr.DestinationPort())
	if !destination.Addr().IsGlobalUnicast() {
		return nil
	}
	data := buf.As(udpHdr.Payload())
	if data.Len() == 0 {
		return nil
	}
	metadata := M.Metadata{
		Source:      M.SocksaddrFromNetIP(source),
		Destination: M.SocksaddrFromNetIP(destination),
	}
	s.handler.NewPacket(s.ctx, source, data.ToOwned(), metadata, func(natConn N.PacketConn) N.PacketWriter {
		headerLen := len(ipHdr) - int(ipHdr.PayloadLength()) + header.UDPMinimumSize
		headerCopy := make([]byte, headerLen)
		copy(headerCopy, ipHdr[:headerLen])
		return &systemUDPPacketWriter6{
			s.tun,
			s.frontHeadroom + PacketOffset,
			headerCopy,
			source,
			s.txChecksumOffload,
		}
	})
	return nil
}

func (s *System) processIPv4ICMP(ipHdr header.IPv4, icmpHdr header.ICMPv4) (bool, error) {
	if icmpHdr.Type() != header.ICMPv4Echo || icmpHdr.Code() != 0 {
		return false, nil
	}
	sourceAddr := ipHdr.SourceAddr()
	destinationAddr := ipHdr.DestinationAddr()
	if destinationAddr != s.inet4Address {
		action, err := s.directNat.Lookup(DirectRouteSession{Source: sourceAddr, Destination: destinationAddr}, func(timeout time.Duration) (DirectRouteDestination, error) {
			return s.handler.PrepareConnection(
				N.NetworkICMP,
				M.SocksaddrFrom(sourceAddr, 0),
				M.SocksaddrFrom(destinationAddr, 0),
				&systemICMPDirectPacketWriter4{s.tun, s.frontHeadroom + PacketOffset, sourceAddr},
				timeout,
			)
		})
		if errors.Is(err, ErrReset) {
			return false, s.rejectIPv4WithICMP(ipHdr, header.ICMPv4HostUnreachable)
		} else if errors.Is(err, ErrDrop) {
			return false, nil
		}
		if action != nil {
			return false, action.WritePacket(buf.As(ipHdr).ToOwned())
		}
	}
	icmpHdr.SetType(header.ICMPv4EchoReply)
	sourceAddress := ipHdr.SourceAddr()
	ipHdr.SetSourceAddr(ipHdr.DestinationAddr())
	ipHdr.SetDestinationAddr(sourceAddress)
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	return true, nil
}

func (s *System) rejectIPv4WithICMP(ipHdr header.IPv4, code header.ICMPv4Code) error {
	frontHeadroom := s.frontHeadroom + PacketOffset
	mtu := s.mtu
	const maxIPData = header.IPv4MinimumProcessableDatagramSize - header.IPv4MinimumSize
	if mtu > maxIPData {
		mtu = maxIPData
	}
	available := mtu - header.ICMPv4MinimumSize
	if available < len(ipHdr)+header.ICMPv4MinimumErrorPayloadSize {
		return nil
	}
	payload := ipHdr
	if len(payload) > available {
		payload = payload[:available]
	}
	newPacket := buf.NewSize(frontHeadroom + header.IPv4MinimumSize + header.ICMPv4MinimumSize + len(payload))
	defer newPacket.Release()
	newPacket.Resize(frontHeadroom, header.IPv4MinimumSize+header.ICMPv4MinimumSize+len(payload))
	newIPHdr := header.IPv4(newPacket.Bytes())
	newIPHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(newPacket.Len()),
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     ipHdr.DestinationAddr(),
		DstAddr:     ipHdr.SourceAddr(),
	})
	newIPHdr.SetChecksum(^newIPHdr.CalculateChecksum())
	icmpHdr := header.ICMPv4(newIPHdr.Payload())
	icmpHdr.SetType(header.ICMPv4DstUnreachable)
	icmpHdr.SetCode(code)
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr[:header.ICMPv4MinimumSize], checksum.Checksum(ipHdr.Payload(), 0)))
	copy(icmpHdr.Payload(), payload)
	if PacketOffset > 0 {
		PacketFillHeader(newPacket.ExtendHeader(PacketOffset), header.IPv4Version)
	} else {
		newPacket.Advance(-s.frontHeadroom)
	}
	return common.Error(s.tun.Write(newPacket.Bytes()))
}

func (s *System) processIPv6ICMP(ipHdr header.IPv6, icmpHdr header.ICMPv6) (bool, error) {
	if icmpHdr.Type() != header.ICMPv6EchoRequest || icmpHdr.Code() != 0 {
		return false, nil
	}
	sourceAddr := ipHdr.SourceAddr()
	destinationAddr := ipHdr.DestinationAddr()
	if destinationAddr != s.inet6Address {
		action, err := s.directNat.Lookup(DirectRouteSession{Source: sourceAddr, Destination: destinationAddr}, func(timeout time.Duration) (DirectRouteDestination, error) {
			return s.handler.PrepareConnection(
				N.NetworkICMP,
				M.SocksaddrFrom(sourceAddr, 0),
				M.SocksaddrFrom(destinationAddr, 0),
				&systemICMPDirectPacketWriter6{s.tun, s.frontHeadroom + PacketOffset, sourceAddr},
				timeout,
			)
		})
		if err != nil {
			if errors.Is(err, ErrReset) {
				return false, s.rejectIPv6WithICMP(ipHdr, header.ICMPv6AddressUnreachable)
			} else if errors.Is(err, ErrDrop) {
				return false, nil
			}
		}
		if action != nil {
			return false, action.WritePacket(buf.As(ipHdr).ToOwned())
		}
	}
	icmpHdr.SetType(header.ICMPv6EchoReply)
	sourceAddress := ipHdr.SourceAddr()
	ipHdr.SetSourceAddr(ipHdr.DestinationAddr())
	ipHdr.SetDestinationAddr(sourceAddress)
	icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmpHdr,
		Src:    ipHdr.SourceAddressSlice(),
		Dst:    ipHdr.DestinationAddressSlice(),
	}))
	return true, nil
}

func (s *System) rejectIPv6WithICMP(ipHdr header.IPv6, code header.ICMPv6Code) error {
	frontHeadroom := s.frontHeadroom + PacketOffset
	mtu := s.mtu
	const maxIPv6Data = header.IPv6MinimumMTU - header.IPv6FixedHeaderSize
	if mtu > maxIPv6Data {
		mtu = maxIPv6Data
	}
	available := mtu - header.ICMPv6ErrorHeaderSize
	if available < header.IPv6MinimumSize {
		return nil
	}
	payload := ipHdr
	if len(payload) > available {
		payload = payload[:available]
	}
	newPacket := buf.NewSize(frontHeadroom + header.IPv6MinimumSize + header.ICMPv6DstUnreachableMinimumSize + len(payload))
	defer newPacket.Release()
	newPacket.Resize(frontHeadroom, header.IPv6MinimumSize+header.ICMPv6DstUnreachableMinimumSize+len(payload))
	newIPHdr := header.IPv6(newPacket.Bytes())
	newIPHdr.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.ICMPv6DstUnreachableMinimumSize + len(payload)),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		SrcAddr:           ipHdr.DestinationAddr(),
		DstAddr:           ipHdr.SourceAddr(),
	})
	icmpHdr := header.ICMPv6(newIPHdr.Payload())
	icmpHdr.SetType(header.ICMPv6DstUnreachable)
	icmpHdr.SetCode(code)
	icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      icmpHdr[:header.ICMPv6DstUnreachableMinimumSize],
		Src:         newIPHdr.SourceAddressSlice(),
		Dst:         newIPHdr.DestinationAddressSlice(),
		PayloadCsum: checksum.Checksum(payload, 0),
		PayloadLen:  len(payload),
	}))
	copy(icmpHdr.Payload(), payload)
	if PacketOffset > 0 {
		PacketFillHeader(newPacket.ExtendHeader(PacketOffset), header.IPv6Version)
	} else {
		newPacket.Advance(-s.frontHeadroom)
	}
	return common.Error(s.tun.Write(newPacket.Bytes()))
}

type systemUDPPacketWriter4 struct {
	tun               Tun
	frontHeadroom     int
	header            []byte
	source            netip.AddrPort
	txChecksumOffload bool
}

func (w *systemUDPPacketWriter4) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	newPacket := buf.NewSize(w.frontHeadroom + len(w.header) + buffer.Len())
	defer newPacket.Release()
	newPacket.Resize(w.frontHeadroom, 0)
	newPacket.Write(w.header)
	newPacket.Write(buffer.Bytes())
	ipHdr := header.IPv4(newPacket.Bytes())
	ipHdr.SetTotalLength(uint16(newPacket.Len()))
	ipHdr.SetDestinationAddress(ipHdr.SourceAddress())
	ipHdr.SetSourceAddr(destination.Addr)
	udpHdr := header.UDP(ipHdr.Payload())
	udpHdr.SetDestinationPort(udpHdr.SourcePort())
	udpHdr.SetSourcePort(destination.Port)
	udpHdr.SetLength(uint16(buffer.Len() + header.UDPMinimumSize))
	if !w.txChecksumOffload {
		udpHdr.SetChecksum(^checksum.Checksum(udpHdr.Payload(), udpHdr.CalculateChecksum(
			header.PseudoHeaderChecksum(header.UDPProtocolNumber, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), ipHdr.PayloadLength()),
		)))
	} else {
		udpHdr.SetChecksum(0)
	}
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	if PacketOffset > 0 {
		PacketFillHeader(newPacket.ExtendHeader(PacketOffset), header.IPv4Version)
	} else {
		newPacket.Advance(-w.frontHeadroom)
	}
	return common.Error(w.tun.Write(newPacket.Bytes()))
}

type systemUDPPacketWriter6 struct {
	tun               Tun
	frontHeadroom     int
	header            []byte
	source            netip.AddrPort
	txChecksumOffload bool
}

func (w *systemUDPPacketWriter6) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	newPacket := buf.NewSize(w.frontHeadroom + len(w.header) + buffer.Len())
	defer newPacket.Release()
	newPacket.Resize(w.frontHeadroom, 0)
	newPacket.Write(w.header)
	newPacket.Write(buffer.Bytes())
	ipHdr := header.IPv6(newPacket.Bytes())
	udpLen := uint16(header.UDPMinimumSize + buffer.Len())
	ipHdr.SetPayloadLength(udpLen)
	ipHdr.SetDestinationAddress(ipHdr.SourceAddress())
	ipHdr.SetSourceAddr(destination.Addr)
	udpHdr := header.UDP(ipHdr.Payload())
	udpHdr.SetDestinationPort(udpHdr.SourcePort())
	udpHdr.SetSourcePort(destination.Port)
	udpHdr.SetLength(udpLen)
	if !w.txChecksumOffload {
		udpHdr.SetChecksum(^checksum.Checksum(udpHdr.Payload(), udpHdr.CalculateChecksum(
			header.PseudoHeaderChecksum(header.UDPProtocolNumber, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), ipHdr.PayloadLength()),
		)))
	} else {
		udpHdr.SetChecksum(0)
	}
	if PacketOffset > 0 {
		PacketFillHeader(newPacket.ExtendHeader(PacketOffset), header.IPv6Version)
	} else {
		newPacket.Advance(-w.frontHeadroom)
	}
	return common.Error(w.tun.Write(newPacket.Bytes()))
}

type systemICMPDirectPacketWriter4 struct {
	tun           Tun
	frontHeadroom int
	source        netip.Addr
}

func (w *systemICMPDirectPacketWriter4) WritePacket(p []byte) error {
	newPacket := buf.NewSize(w.frontHeadroom + len(p))
	defer newPacket.Release()
	newPacket.Resize(w.frontHeadroom, 0)
	newPacket.Write(p)
	ipHdr := header.IPv4(newPacket.Bytes())
	ipHdr.SetDestinationAddr(w.source)
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	if PacketOffset > 0 {
		PacketFillHeader(newPacket.ExtendHeader(PacketOffset), header.IPv4Version)
	} else {
		newPacket.Advance(-w.frontHeadroom)
	}
	return common.Error(w.tun.Write(newPacket.Bytes()))
}

type systemICMPDirectPacketWriter6 struct {
	tun           Tun
	frontHeadroom int
	source        netip.Addr
}

func (w *systemICMPDirectPacketWriter6) WritePacket(p []byte) error {
	newPacket := buf.NewSize(w.frontHeadroom + len(p))
	defer newPacket.Release()
	newPacket.Resize(w.frontHeadroom, 0)
	newPacket.Write(p)
	ipHdr := header.IPv6(newPacket.Bytes())
	ipHdr.SetDestinationAddr(w.source)
	if PacketOffset > 0 {
		PacketFillHeader(newPacket.ExtendHeader(PacketOffset), header.IPv6Version)
	} else {
		newPacket.Advance(-w.frontHeadroom)
	}
	return common.Error(w.tun.Write(newPacket.Bytes()))
}
