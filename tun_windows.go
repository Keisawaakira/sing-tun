package tun

import (
	"crypto/md5"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/metacubex/sing/common"
	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/sing/common/windnsapi"

	"github.com/metacubex/sing-tun/internal/winipcfg"
	"github.com/metacubex/sing-tun/internal/winsys"
	"github.com/metacubex/sing-tun/internal/wintun"

	"golang.org/x/sys/windows"
)

var TunnelType = "sing-tun"

type NativeTun struct {
	adapter     *wintun.Adapter
	options     Options
	session     wintun.Session
	readWait    windows.Handle
	rate        rateJuggler
	running     sync.WaitGroup
	closeOnce   sync.Once
	close       atomic.Int32
	fwpmSession    uintptr
	fwpmSubLayer   windows.GUID
	fwpmPermitApps map[string]struct{}
}

func New(options Options) (WinTun, error) {
	if options.FileDescriptor != 0 {
		return nil, os.ErrInvalid
	}
	adapter, err := wintun.CreateAdapter(options.Name, TunnelType, generateGUIDByDeviceName(options.Name))
	if err != nil {
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		createErr := err
		adapter, err = wintun.OpenAdapter(options.Name)
		if err != nil {
			return nil, E.Errors(E.Cause(createErr, "create adapter"), E.Cause(err, "open existing adapter"))
		}
	}
	nativeTun := &NativeTun{
		adapter: adapter,
		options: options,
	}
	session, err := adapter.StartSession(wintun.RingCapacityMax)
	if err != nil {
		return nil, err
	}
	nativeTun.session = session
	nativeTun.readWait = session.ReadWaitEvent()
	err = nativeTun.configure()
	if err != nil {
		session.End()
		adapter.Close()
		return nil, err
	}
	return nativeTun, nil
}

func (t *NativeTun) configure() error {
	luid := winipcfg.LUID(t.adapter.LUID())
	if len(t.options.Inet4Address) > 0 {
		err := luid.SetIPAddressesForFamily(winipcfg.AddressFamily(windows.AF_INET), t.options.Inet4Address)
		if err != nil {
			return E.Cause(err, "set ipv4 address")
		}
		if t.options.AutoRoute && !t.options.EXP_DisableDNSHijack {
			dnsServers := common.Filter(t.options.DNSServers, netip.Addr.Is4)
			if len(dnsServers) == 0 && HasNextAddress(t.options.Inet4Address[0], 1) {
				dnsServers = []netip.Addr{t.options.Inet4Address[0].Addr().Next()}
			}
			if len(dnsServers) > 0 {
				err = luid.SetDNS(winipcfg.AddressFamily(windows.AF_INET), dnsServers, nil)
				if err != nil {
					return E.Cause(err, "set ipv4 dns")
				}
			}
		} else {
			err = luid.SetDNS(winipcfg.AddressFamily(windows.AF_INET), nil, nil)
			if err != nil {
				return E.Cause(err, "set ipv4 dns")
			}
		}
	}
	if len(t.options.Inet6Address) > 0 {
		err := luid.SetIPAddressesForFamily(winipcfg.AddressFamily(windows.AF_INET6), t.options.Inet6Address)
		if err != nil {
			return E.Cause(err, "set ipv6 address")
		}
		if t.options.AutoRoute && !t.options.EXP_DisableDNSHijack {
			dnsServers := common.Filter(t.options.DNSServers, netip.Addr.Is6)
			if len(dnsServers) == 0 && HasNextAddress(t.options.Inet6Address[0], 1) {
				dnsServers = []netip.Addr{t.options.Inet6Address[0].Addr().Next()}
			}
			if len(dnsServers) > 0 {
				err = luid.SetDNS(winipcfg.AddressFamily(windows.AF_INET6), dnsServers, nil)
				if err != nil {
					return E.Cause(err, "set ipv6 dns")
				}
			}
		} else {
			err = luid.SetDNS(winipcfg.AddressFamily(windows.AF_INET6), nil, nil)
			if err != nil {
				return E.Cause(err, "set ipv6 dns")
			}
		}
	}
	if len(t.options.Inet4Address) > 0 || len(t.options.Inet6Address) > 0 {
		_ = luid.DisableDNSRegistration()
	}
	if t.options.AutoRoute {
		gateway4, gateway6 := t.options.Inet4GatewayAddr(), t.options.Inet6GatewayAddr()
		routeRanges, err := t.options.BuildAutoRouteRanges(false)
		if err != nil {
			return err
		}
		for _, routeRange := range routeRanges {
			if routeRange.Addr().Is4() {
				err = luid.AddRoute(routeRange, gateway4, 0)
			} else {
				err = luid.AddRoute(routeRange, gateway6, 0)
			}
		}
		if err != nil {
			return err
		}
		err = windnsapi.FlushResolverCache()
		if err != nil {
			return err
		}
	}
	if len(t.options.Inet4Address) > 0 {
		inetIf, err := luid.IPInterface(winipcfg.AddressFamily(windows.AF_INET))
		if err != nil {
			return err
		}
		inetIf.ForwardingEnabled = true
		inetIf.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		inetIf.DadTransmits = 0
		inetIf.ManagedAddressConfigurationSupported = false
		inetIf.OtherStatefulConfigurationSupported = false
		inetIf.NLMTU = t.options.MTU
		if t.options.AutoRoute {
			inetIf.UseAutomaticMetric = false
			inetIf.Metric = 0
		}
		err = inetIf.Set()
		if err != nil {
			return E.Cause(err, "set ipv4 options")
		}
	}
	if len(t.options.Inet6Address) > 0 {
		inet6If, err := luid.IPInterface(winipcfg.AddressFamily(windows.AF_INET6))
		if err != nil {
			return err
		}
		inet6If.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		inet6If.DadTransmits = 0
		inet6If.ManagedAddressConfigurationSupported = false
		inet6If.OtherStatefulConfigurationSupported = false
		inet6If.NLMTU = t.options.MTU
		if t.options.AutoRoute {
			inet6If.UseAutomaticMetric = false
			inet6If.Metric = 0
		}
		err = inet6If.Set()
		if err != nil {
			return E.Cause(err, "set ipv6 options")
		}
	}

	if t.options.AutoRoute && (t.options.StrictRoute || len(t.options.ExcludeProcess) > 0 || len(t.options.ExcludeProcessPath) > 0) {
		if err := t.configureAutoRouteFilters(); err != nil {
			return err
		}
	}

	return nil
}


func (t *NativeTun) configureAutoRouteFilters() error {
	if err := t.ensureWFPMSession(); err != nil {
		return err
	}

	if t.options.StrictRoute {
		processAppID, err := winsys.GetCurrentProcessAppID()
		if err != nil {
			return err
		}
		defer winsys.FwpmFreeMemory0(unsafe.Pointer(&processAppID))

		if err := t.addPermitFilterForAppID(processAppID, "protect", 13); err != nil {
			return err
		}
		if len(t.options.Inet6Address) == 0 {
			if err := t.addBlockIPv6Filter(); err != nil {
				return err
			}
		}
		if err := t.addInterfacePermitFilters(); err != nil {
			return err
		}
		if !t.options.EXP_DisableDNSHijack {
			if err := t.addBlockDNSFilters(); err != nil {
				return err
			}
		}
	}

	resolvedPaths, unresolvedNames, err := resolveExcludedProcessPaths(t.options.ExcludeProcess, t.options.ExcludeProcessPath)
	if err != nil {
		return err
	}
	for _, path := range resolvedPaths {
		if err := t.addPermitFilterForPath(path); err != nil {
			return err
		}
	}
	if t.options.Logger != nil && len(unresolvedNames) > 0 {
		t.options.Logger.Warn("tun exclude-process unresolved names: ", strings.Join(unresolvedNames, ", "))
	}
	return nil
}

func (t *NativeTun) ensureWFPMSession() error {
	if t.fwpmSession != 0 {
		return nil
	}

	var engine uintptr
	session := &winsys.FWPM_SESSION0{Flags: winsys.FWPM_SESSION_FLAG_DYNAMIC}
	err := winsys.FwpmEngineOpen0(nil, winsys.RPC_C_AUTHN_DEFAULT, nil, session, unsafe.Pointer(&engine))
	if err != nil {
		return os.NewSyscallError("FwpmEngineOpen0", err)
	}

	subLayerKey, err := windows.GenerateGUID()
	if err != nil {
		winsys.FwpmEngineClose0(engine)
		return os.NewSyscallError("CoCreateGuid", err)
	}

	subLayer := winsys.FWPM_SUBLAYER0{}
	subLayer.SubLayerKey = subLayerKey
	subLayer.DisplayData = winsys.CreateDisplayData(TunnelType, "auto-route rules")
	subLayer.Weight = math.MaxUint16
	err = winsys.FwpmSubLayerAdd0(engine, &subLayer, 0)
	if err != nil {
		winsys.FwpmEngineClose0(engine)
		return os.NewSyscallError("FwpmSubLayerAdd0", err)
	}

	t.fwpmSession = engine
	t.fwpmSubLayer = subLayerKey
	if t.fwpmPermitApps == nil {
		t.fwpmPermitApps = make(map[string]struct{})
	}
	return nil
}

func (t *NativeTun) addPermitFilterForAppID(appID *winsys.FWP_BYTE_BLOB, description string, weight uint8) error {
	var filterID uint64
	permitCondition := []winsys.FWPM_FILTER_CONDITION0{{}}
	permitCondition[0].FieldKey = winsys.FWPM_CONDITION_ALE_APP_ID
	permitCondition[0].MatchType = winsys.FWP_MATCH_EQUAL
	permitCondition[0].ConditionValue.Type = winsys.FWP_BYTE_BLOB_TYPE
	permitCondition[0].ConditionValue.Value = uintptr(unsafe.Pointer(appID))

	permitFilter4 := winsys.FWPM_FILTER0{}
	permitFilter4.FilterCondition = &permitCondition[0]
	permitFilter4.NumFilterConditions = 1
	permitFilter4.DisplayData = winsys.CreateDisplayData(TunnelType, description+" ipv4")
	permitFilter4.SubLayerKey = t.fwpmSubLayer
	permitFilter4.LayerKey = winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V4
	permitFilter4.Action.Type = winsys.FWP_ACTION_PERMIT
	permitFilter4.Weight.Type = winsys.FWP_UINT8
	permitFilter4.Weight.Value = uintptr(weight)
	permitFilter4.Flags = winsys.FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT
	if err := winsys.FwpmFilterAdd0(t.fwpmSession, &permitFilter4, 0, &filterID); err != nil {
		return os.NewSyscallError("FwpmFilterAdd0", err)
	}

	permitFilter6 := winsys.FWPM_FILTER0{}
	permitFilter6.FilterCondition = &permitCondition[0]
	permitFilter6.NumFilterConditions = 1
	permitFilter6.DisplayData = winsys.CreateDisplayData(TunnelType, description+" ipv6")
	permitFilter6.SubLayerKey = t.fwpmSubLayer
	permitFilter6.LayerKey = winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V6
	permitFilter6.Action.Type = winsys.FWP_ACTION_PERMIT
	permitFilter6.Weight.Type = winsys.FWP_UINT8
	permitFilter6.Weight.Value = uintptr(weight)
	permitFilter6.Flags = winsys.FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT
	if err := winsys.FwpmFilterAdd0(t.fwpmSession, &permitFilter6, 0, &filterID); err != nil {
		return os.NewSyscallError("FwpmFilterAdd0", err)
	}

	return nil
}

func (t *NativeTun) addPermitFilterForPath(path string) error {
	normalizedPath := normalizeProcessPath(path)
	if normalizedPath == "" {
		return nil
	}
	if _, exists := t.fwpmPermitApps[normalizedPath]; exists {
		return nil
	}
	appID, err := winsys.GetAppIDByPath(normalizedPath)
	if err != nil {
		return err
	}
	defer winsys.FwpmFreeMemory0(unsafe.Pointer(&appID))
	if err := t.addPermitFilterForAppID(appID, processFilterDescription(normalizedPath), 14); err != nil {
		return err
	}
	t.fwpmPermitApps[normalizedPath] = struct{}{}
	return nil
}

func (t *NativeTun) addBlockIPv6Filter() error {
	var filterID uint64
	blockFilter := winsys.FWPM_FILTER0{}
	blockFilter.DisplayData = winsys.CreateDisplayData(TunnelType, "block ipv6")
	blockFilter.SubLayerKey = t.fwpmSubLayer
	blockFilter.LayerKey = winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V6
	blockFilter.Action.Type = winsys.FWP_ACTION_BLOCK
	blockFilter.Weight.Type = winsys.FWP_UINT8
	blockFilter.Weight.Value = uintptr(12)
	if err := winsys.FwpmFilterAdd0(t.fwpmSession, &blockFilter, 0, &filterID); err != nil {
		return os.NewSyscallError("FwpmFilterAdd0", err)
	}
	return nil
}

func (t *NativeTun) addInterfacePermitFilters() error {
	netInterface, err := net.InterfaceByName(t.options.Name)
	if err != nil {
		return err
	}

	var filterID uint64
	tunCondition := []winsys.FWPM_FILTER_CONDITION0{{}}
	tunCondition[0].FieldKey = winsys.FWPM_CONDITION_LOCAL_INTERFACE_INDEX
	tunCondition[0].MatchType = winsys.FWP_MATCH_EQUAL
	tunCondition[0].ConditionValue.Type = winsys.FWP_UINT32
	tunCondition[0].ConditionValue.Value = uintptr(uint32(netInterface.Index))

	if len(t.options.Inet4Address) > 0 {
		tunFilter4 := winsys.FWPM_FILTER0{}
		tunFilter4.FilterCondition = &tunCondition[0]
		tunFilter4.NumFilterConditions = 1
		tunFilter4.DisplayData = winsys.CreateDisplayData(TunnelType, "allow ipv4")
		tunFilter4.SubLayerKey = t.fwpmSubLayer
		tunFilter4.LayerKey = winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V4
		tunFilter4.Action.Type = winsys.FWP_ACTION_PERMIT
		tunFilter4.Weight.Type = winsys.FWP_UINT8
		tunFilter4.Weight.Value = uintptr(11)
		if err := winsys.FwpmFilterAdd0(t.fwpmSession, &tunFilter4, 0, &filterID); err != nil {
			return os.NewSyscallError("FwpmFilterAdd0", err)
		}
	}

	if len(t.options.Inet6Address) > 0 {
		tunFilter6 := winsys.FWPM_FILTER0{}
		tunFilter6.FilterCondition = &tunCondition[0]
		tunFilter6.NumFilterConditions = 1
		tunFilter6.DisplayData = winsys.CreateDisplayData(TunnelType, "allow ipv6")
		tunFilter6.SubLayerKey = t.fwpmSubLayer
		tunFilter6.LayerKey = winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V6
		tunFilter6.Action.Type = winsys.FWP_ACTION_PERMIT
		tunFilter6.Weight.Type = winsys.FWP_UINT8
		tunFilter6.Weight.Value = uintptr(11)
		if err := winsys.FwpmFilterAdd0(t.fwpmSession, &tunFilter6, 0, &filterID); err != nil {
			return os.NewSyscallError("FwpmFilterAdd0", err)
		}
	}

	return nil
}

func (t *NativeTun) addBlockDNSFilters() error {
	var filterID uint64
	blockDNSCondition := []winsys.FWPM_FILTER_CONDITION0{{}}
	blockDNSCondition[0].FieldKey = winsys.FWPM_CONDITION_IP_REMOTE_PORT
	blockDNSCondition[0].MatchType = winsys.FWP_MATCH_EQUAL
	blockDNSCondition[0].ConditionValue.Type = winsys.FWP_UINT16
	blockDNSCondition[0].ConditionValue.Value = uintptr(uint16(53))

	blockDNSFilter4 := winsys.FWPM_FILTER0{}
	blockDNSFilter4.FilterCondition = &blockDNSCondition[0]
	blockDNSFilter4.NumFilterConditions = 1
	blockDNSFilter4.DisplayData = winsys.CreateDisplayData(TunnelType, "block ipv4 dns")
	blockDNSFilter4.SubLayerKey = t.fwpmSubLayer
	blockDNSFilter4.LayerKey = winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V4
	blockDNSFilter4.Action.Type = winsys.FWP_ACTION_BLOCK
	blockDNSFilter4.Weight.Type = winsys.FWP_UINT8
	blockDNSFilter4.Weight.Value = uintptr(10)
	if err := winsys.FwpmFilterAdd0(t.fwpmSession, &blockDNSFilter4, 0, &filterID); err != nil {
		return os.NewSyscallError("FwpmFilterAdd0", err)
	}

	blockDNSFilter6 := winsys.FWPM_FILTER0{}
	blockDNSFilter6.FilterCondition = &blockDNSCondition[0]
	blockDNSFilter6.NumFilterConditions = 1
	blockDNSFilter6.DisplayData = winsys.CreateDisplayData(TunnelType, "block ipv6 dns")
	blockDNSFilter6.SubLayerKey = t.fwpmSubLayer
	blockDNSFilter6.LayerKey = winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V6
	blockDNSFilter6.Action.Type = winsys.FWP_ACTION_BLOCK
	blockDNSFilter6.Weight.Type = winsys.FWP_UINT8
	blockDNSFilter6.Weight.Value = uintptr(10)
	if err := winsys.FwpmFilterAdd0(t.fwpmSession, &blockDNSFilter6, 0, &filterID); err != nil {
		return os.NewSyscallError("FwpmFilterAdd0", err)
	}

	return nil
}

func (t *NativeTun) waitReadEvent() {
	windows.WaitForSingleObject(t.readWait, windows.INFINITE)
}

func (t *NativeTun) shouldSpin(start int64) bool {
	return t.rate.current.Load() >= spinloopRateThreshold &&
		uint64(start-t.rate.nextStartTime.Load()) <= rateMeasurementGranularity*2
}

func (t *NativeTun) Read(p []byte) (n int, err error) {
	t.running.Add(1)
	defer t.running.Done()
retry:
	if t.close.Load() == 1 {
		return 0, os.ErrClosed
	}
	start := nanotime()
	shouldSpin := t.shouldSpin(start)
	for {
		if t.close.Load() == 1 {
			return 0, os.ErrClosed
		}
		var packet []byte
		packet, err = t.session.ReceivePacket()
		switch err {
		case nil:
			n = copy(p, packet)
			t.session.ReleaseReceivePacket(packet)
			t.rate.update(uint64(n))
			return
		case windows.ERROR_NO_MORE_ITEMS:
			if shouldSpin && uint64(nanotime()-start) < spinloopDuration {
				procyield(spinloopCycles)
				continue
			}
			t.waitReadEvent()
			goto retry
		case windows.ERROR_HANDLE_EOF:
			return 0, os.ErrClosed
		case windows.ERROR_INVALID_DATA:
			err = errors.New("send ring corrupt")
			return 0, err
		}
		return 0, fmt.Errorf("read failed: %w", err)
	}
}

func (t *NativeTun) ReadPacket() ([]byte, func(), error) {
	t.running.Add(1)
retry:
	if t.close.Load() == 1 {
		t.running.Done()
		return nil, nil, os.ErrClosed
	}
	start := nanotime()
	shouldSpin := t.shouldSpin(start)
	for {
		if t.close.Load() == 1 {
			t.running.Done()
			return nil, nil, os.ErrClosed
		}
		packet, err := t.session.ReceivePacket()
		switch err {
		case nil:
			packetSize := len(packet)
			t.rate.update(uint64(packetSize))
			return packet, func() {
				t.session.ReleaseReceivePacket(packet)
				t.running.Done()
			}, nil
		case windows.ERROR_NO_MORE_ITEMS:
			if shouldSpin && uint64(nanotime()-start) < spinloopDuration {
				procyield(spinloopCycles)
				continue
			}
			t.waitReadEvent()
			goto retry
		case windows.ERROR_HANDLE_EOF:
			t.running.Done()
			return nil, nil, os.ErrClosed
		case windows.ERROR_INVALID_DATA:
			t.running.Done()
			return nil, nil, errors.New("send ring corrupt")
		}
		t.running.Done()
		return nil, nil, fmt.Errorf("read failed: %w", err)
	}
}

func (t *NativeTun) TryReadPacket() ([]byte, func(), bool, error) {
	t.running.Add(1)
	if t.close.Load() == 1 {
		t.running.Done()
		return nil, nil, false, os.ErrClosed
	}
	packet, err := t.session.ReceivePacket()
	switch err {
	case nil:
		t.rate.update(uint64(len(packet)))
		return packet, func() {
			t.session.ReleaseReceivePacket(packet)
			t.running.Done()
		}, true, nil
	case windows.ERROR_NO_MORE_ITEMS:
		t.running.Done()
		return nil, nil, false, nil
	case windows.ERROR_HANDLE_EOF:
		t.running.Done()
		return nil, nil, false, os.ErrClosed
	case windows.ERROR_INVALID_DATA:
		t.running.Done()
		return nil, nil, false, errors.New("send ring corrupt")
	default:
		t.running.Done()
		return nil, nil, false, fmt.Errorf("read failed: %w", err)
	}
}

func (t *NativeTun) ReadFunc(block func(b []byte)) error {
	t.running.Add(1)
	defer t.running.Done()
retry:
	if t.close.Load() == 1 {
		return os.ErrClosed
	}
	start := nanotime()
	shouldSpin := t.shouldSpin(start)
	for {
		if t.close.Load() == 1 {
			return os.ErrClosed
		}
		packet, err := t.session.ReceivePacket()
		switch err {
		case nil:
			packetSize := len(packet)
			block(packet)
			t.session.ReleaseReceivePacket(packet)
			t.rate.update(uint64(packetSize))
			return nil
		case windows.ERROR_NO_MORE_ITEMS:
			if shouldSpin && uint64(nanotime()-start) < spinloopDuration {
				procyield(spinloopCycles)
				continue
			}
			t.waitReadEvent()
			goto retry
		case windows.ERROR_HANDLE_EOF:
			return os.ErrClosed
		case windows.ERROR_INVALID_DATA:
			return errors.New("send ring corrupt")
		}
		return fmt.Errorf("read failed: %w", err)
	}
}

func (t *NativeTun) Write(p []byte) (n int, err error) {
	t.running.Add(1)
	defer t.running.Done()
	if t.close.Load() == 1 {
		return 0, os.ErrClosed
	}
	start := nanotime()
	shouldSpin := t.shouldSpin(start)
	for {
		packet, allocErr := t.session.AllocateSendPacket(len(p))
		if allocErr == nil {
			copy(packet, p)
			t.rate.update(uint64(len(p)))
			t.session.SendPacket(packet)
			return len(p), nil
		}
		switch allocErr {
		case windows.ERROR_HANDLE_EOF:
			return 0, os.ErrClosed
		case windows.ERROR_BUFFER_OVERFLOW:
			if shouldSpin && uint64(nanotime()-start) < spinloopDuration {
				procyield(spinloopCycles)
				continue
			}
			return 0, nil // Dropping when ring is full.
		}
		return 0, fmt.Errorf("write failed: %w", allocErr)
	}
}

func (t *NativeTun) write(packetElementList [][]byte) (n int, err error) {
	t.running.Add(1)
	defer t.running.Done()
	if t.close.Load() == 1 {
		return 0, os.ErrClosed
	}
	var packetSize int
	for _, packetElement := range packetElementList {
		packetSize += len(packetElement)
	}
	start := nanotime()
	shouldSpin := t.shouldSpin(start)
	for {
		packet, allocErr := t.session.AllocateSendPacket(packetSize)
		if allocErr == nil {
			t.rate.update(uint64(packetSize))
			var index int
			for _, packetElement := range packetElementList {
				index += copy(packet[index:], packetElement)
			}
			t.session.SendPacket(packet)
			return
		}
		switch allocErr {
		case windows.ERROR_HANDLE_EOF:
			return 0, os.ErrClosed
		case windows.ERROR_BUFFER_OVERFLOW:
			if shouldSpin && uint64(nanotime()-start) < spinloopDuration {
				procyield(spinloopCycles)
				continue
			}
			return 0, nil // Dropping when ring is full.
		}
		return 0, fmt.Errorf("write failed: %w", allocErr)
	}
}

func (t *NativeTun) Close() error {
	var err error
	t.closeOnce.Do(func() {
		t.close.Store(1)
		windows.SetEvent(t.readWait)
		t.running.Wait()
		t.session.End()
		t.adapter.Close()
		if t.fwpmSession != 0 {
			winsys.FwpmEngineClose0(t.fwpmSession)
		}
		if t.options.AutoRoute {
			windnsapi.FlushResolverCache()
		}
	})
	return err
}

func generateGUIDByDeviceName(name string) *windows.GUID {
	hash := md5.New()
	hash.Write([]byte("wintun"))
	hash.Write([]byte(name))
	sum := hash.Sum(nil)
	return (*windows.GUID)(unsafe.Pointer(&sum[0]))
}

//go:linkname procyield runtime.procyield
func procyield(cycles uint32)

//go:linkname nanotime runtime.nanotime
func nanotime() int64

type rateJuggler struct {
	current       atomic.Uint64
	nextByteCount atomic.Uint64
	nextStartTime atomic.Int64
	changing      atomic.Int32
}

func (rate *rateJuggler) update(packetLen uint64) {
	now := nanotime()
	total := rate.nextByteCount.Add(packetLen)
	period := uint64(now - rate.nextStartTime.Load())
	if period >= rateMeasurementGranularity {
		if !rate.changing.CompareAndSwap(0, 1) {
			return
		}
		rate.nextStartTime.Store(now)
		rate.current.Store(total * uint64(time.Second/time.Nanosecond) / period)
		rate.nextByteCount.Store(0)
		rate.changing.Store(0)
	}
}

const (
	rateMeasurementGranularity = uint64((time.Second / 2) / time.Nanosecond)
	spinloopRateThreshold      = 800000000 / 8                                   // 800mbps
	spinloopDuration           = uint64(time.Millisecond / 10 / time.Nanosecond) // 100us
	spinloopCycles             = 8
)
