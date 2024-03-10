package tun

import (
	"encoding/binary"
	"golang.org/x/sys/windows"
	"net"
	"sync"
	"unsafe"

	"github.com/sagernet/sing-tun/internal/winipcfg"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
)

type networkUpdateMonitor struct {
	routeListener     *winipcfg.RouteChangeCallback
	interfaceListener *winipcfg.InterfaceChangeCallback
	errorHandler      E.Handler

	access    sync.Mutex
	callbacks list.List[NetworkUpdateCallback]
	logger    logger.Logger
}

func NewNetworkUpdateMonitor(logger logger.Logger) (NetworkUpdateMonitor, error) {
	return &networkUpdateMonitor{
		logger: logger,
	}, nil
}

func (m *networkUpdateMonitor) Start() error {
	routeListener, err := winipcfg.RegisterRouteChangeCallback(func(notificationType winipcfg.MibNotificationType, route *winipcfg.MibIPforwardRow2) {
		m.emit()
	})
	if err != nil {
		return err
	}
	m.routeListener = routeListener
	interfaceListener, err := winipcfg.RegisterInterfaceChangeCallback(func(notificationType winipcfg.MibNotificationType, iface *winipcfg.MibIPInterfaceRow) {
		m.emit()
	})
	if err != nil {
		routeListener.Unregister()
		return err
	}
	m.interfaceListener = interfaceListener
	return nil
}

func (m *networkUpdateMonitor) Close() error {
	if m.routeListener != nil {
		m.routeListener.Unregister()
		m.routeListener = nil
	}
	if m.interfaceListener != nil {
		m.interfaceListener.Unregister()
		m.interfaceListener = nil
	}
	return nil
}

func getIpAddr(interfaceIndex int) (uint32, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return 0, err
	}

	for _, inter := range interfaces {
		if inter.Index != interfaceIndex {
			continue
		}

		addrs, err := inter.Addrs()
		if err != nil {
			return 0, err
		}

		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}

			bytes := ip.To4()

			if bytes == nil {
				continue
			}

			return binary.LittleEndian.Uint32(bytes), nil
		}
	}

	return 0, ErrNoRoute
}

func (m *defaultInterfaceMonitor) checkUpdate() error {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return err
	}

	dest := binary.LittleEndian.Uint32(net.ParseIP("223.5.5.5").To4())

	lowestMetric := ^uint32(0)
	alias := ""
	var index uint32

	for _, row := range rows {
		if row.DestinationPrefix.PrefixLength != 0 {
			continue
		}

		ifrow, err := row.InterfaceLUID.Interface()
		if err != nil || ifrow.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}

		if ifrow.Type == winipcfg.IfTypePropVirtual || ifrow.Type == winipcfg.IfTypeSoftwareLoopback {
			continue
		}

		if ifrow.Alias() == "" {
			continue
		}

		source, err := getIpAddr(int(ifrow.InterfaceIndex))
		if err != nil {
			continue
		}

		file := winipcfg.IcmpCreateFile()

		var buf = [1]byte{}

		option := winipcfg.IcmpOption{
			Ttl:   255,
			Flags: 0,
		}

		var reply = winipcfg.IcmpReply{}
		var replySize = uint32(unsafe.Sizeof(reply))

		ret := winipcfg.IcmpSendEcho2Ex(
			file,
			0,
			0,
			0,
			source,
			dest,
			uintptr(unsafe.Pointer(&buf[0])),
			0,
			&option,
			uintptr(unsafe.Pointer(&reply)),
			replySize, 5000)

		winipcfg.IcmpCloseHandle(file)

		if ret == 0 || reply.Status != 0 {
			continue
		}

		iface, err := row.InterfaceLUID.IPInterface(windows.AF_INET)
		if err != nil {
			continue
		}

		metric := row.Metric + iface.Metric
		if metric < lowestMetric {
			lowestMetric = metric
			alias = ifrow.Alias()
			index = ifrow.InterfaceIndex
		}

		index = ifrow.InterfaceIndex
		alias = ifrow.Alias()
	}

	if alias == "" {
		return ErrNoRoute
	}

	oldInterface := m.defaultInterfaceName
	oldIndex := m.defaultInterfaceIndex

	m.defaultInterfaceName = alias
	m.defaultInterfaceIndex = int(index)

	if oldInterface == m.defaultInterfaceName && oldIndex == m.defaultInterfaceIndex {
		return nil
	}

	m.emit(EventInterfaceUpdate)
	return nil
}
