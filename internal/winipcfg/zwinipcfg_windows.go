// Code generated by 'go generate'; DO NOT EDIT.

package winipcfg

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var _ unsafe.Pointer

// Do the interface allocations only once for common
// Errno values.
const (
	errnoERROR_IO_PENDING = 997
)

var (
	errERROR_IO_PENDING error = syscall.Errno(errnoERROR_IO_PENDING)
	errERROR_EINVAL     error = syscall.EINVAL
)

// errnoErr returns common boxed Errno values, to prevent
// allocations at runtime.
func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return errERROR_EINVAL
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}
	// TODO: add more here, after collecting data on the common
	// error values see on Windows. (perhaps when running
	// all.bat?)
	return e
}

var (
	modiphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	procCancelMibChangeNotify2          = modiphlpapi.NewProc("CancelMibChangeNotify2")
	procConvertInterfaceGuidToLuid      = modiphlpapi.NewProc("ConvertInterfaceGuidToLuid")
	procConvertInterfaceIndexToLuid     = modiphlpapi.NewProc("ConvertInterfaceIndexToLuid")
	procConvertInterfaceLuidToGuid      = modiphlpapi.NewProc("ConvertInterfaceLuidToGuid")
	procCreateAnycastIpAddressEntry     = modiphlpapi.NewProc("CreateAnycastIpAddressEntry")
	procCreateIpForwardEntry2           = modiphlpapi.NewProc("CreateIpForwardEntry2")
	procCreateUnicastIpAddressEntry     = modiphlpapi.NewProc("CreateUnicastIpAddressEntry")
	procDeleteAnycastIpAddressEntry     = modiphlpapi.NewProc("DeleteAnycastIpAddressEntry")
	procDeleteIpForwardEntry2           = modiphlpapi.NewProc("DeleteIpForwardEntry2")
	procDeleteUnicastIpAddressEntry     = modiphlpapi.NewProc("DeleteUnicastIpAddressEntry")
	procFreeMibTable                    = modiphlpapi.NewProc("FreeMibTable")
	procGetAnycastIpAddressEntry        = modiphlpapi.NewProc("GetAnycastIpAddressEntry")
	procGetAnycastIpAddressTable        = modiphlpapi.NewProc("GetAnycastIpAddressTable")
	procGetIfEntry2                     = modiphlpapi.NewProc("GetIfEntry2")
	procGetIfTable2Ex                   = modiphlpapi.NewProc("GetIfTable2Ex")
	procGetIpForwardEntry2              = modiphlpapi.NewProc("GetIpForwardEntry2")
	procGetIpForwardTable2              = modiphlpapi.NewProc("GetIpForwardTable2")
	procGetIpInterfaceEntry             = modiphlpapi.NewProc("GetIpInterfaceEntry")
	procGetIpInterfaceTable             = modiphlpapi.NewProc("GetIpInterfaceTable")
	procGetUnicastIpAddressEntry        = modiphlpapi.NewProc("GetUnicastIpAddressEntry")
	procGetUnicastIpAddressTable        = modiphlpapi.NewProc("GetUnicastIpAddressTable")
	procInitializeIpForwardEntry        = modiphlpapi.NewProc("InitializeIpForwardEntry")
	procInitializeIpInterfaceEntry      = modiphlpapi.NewProc("InitializeIpInterfaceEntry")
	procInitializeUnicastIpAddressEntry = modiphlpapi.NewProc("InitializeUnicastIpAddressEntry")
	procNotifyIpInterfaceChange         = modiphlpapi.NewProc("NotifyIpInterfaceChange")
	procNotifyRouteChange2              = modiphlpapi.NewProc("NotifyRouteChange2")
	procNotifyUnicastIpAddressChange    = modiphlpapi.NewProc("NotifyUnicastIpAddressChange")
	procSetInterfaceDnsSettings         = modiphlpapi.NewProc("SetInterfaceDnsSettings")
	procSetIpForwardEntry2              = modiphlpapi.NewProc("SetIpForwardEntry2")
	procSetIpInterfaceEntry             = modiphlpapi.NewProc("SetIpInterfaceEntry")
	procSetUnicastIpAddressEntry        = modiphlpapi.NewProc("SetUnicastIpAddressEntry")
	procIcmpSendEcho2Ex                 = modiphlpapi.NewProc("IcmpSendEcho2Ex")
	procIcmpCreateFile                  = modiphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle                 = modiphlpapi.NewProc("IcmpCloseHandle")
)

func cancelMibChangeNotify2(notificationHandle windows.Handle) (ret error) {
	r0, _, _ := syscall.Syscall(procCancelMibChangeNotify2.Addr(), 1, uintptr(notificationHandle), 0, 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func convertInterfaceGUIDToLUID(interfaceGUID *windows.GUID, interfaceLUID *LUID) (ret error) {
	r0, _, _ := syscall.Syscall(procConvertInterfaceGuidToLuid.Addr(), 2, uintptr(unsafe.Pointer(interfaceGUID)), uintptr(unsafe.Pointer(interfaceLUID)), 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func convertInterfaceIndexToLUID(interfaceIndex uint32, interfaceLUID *LUID) (ret error) {
	r0, _, _ := syscall.Syscall(procConvertInterfaceIndexToLuid.Addr(), 2, uintptr(interfaceIndex), uintptr(unsafe.Pointer(interfaceLUID)), 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func convertInterfaceLUIDToGUID(interfaceLUID *LUID, interfaceGUID *windows.GUID) (ret error) {
	r0, _, _ := syscall.Syscall(procConvertInterfaceLuidToGuid.Addr(), 2, uintptr(unsafe.Pointer(interfaceLUID)), uintptr(unsafe.Pointer(interfaceGUID)), 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func createAnycastIPAddressEntry(row *MibAnycastIPAddressRow) (ret error) {
	r0, _, _ := syscall.Syscall(procCreateAnycastIpAddressEntry.Addr(), 1, uintptr(unsafe.Pointer(row)), 0, 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func createIPForwardEntry2(route *MibIPforwardRow2) (ret error) {
	r0, _, _ := syscall.Syscall(procCreateIpForwardEntry2.Addr(), 1, uintptr(unsafe.Pointer(route)), 0, 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func createUnicastIPAddressEntry(row *MibUnicastIPAddressRow) (ret error) {
	r0, _, _ := syscall.Syscall(procCreateUnicastIpAddressEntry.Addr(), 1, uintptr(unsafe.Pointer(row)), 0, 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func deleteAnycastIPAddressEntry(row *MibAnycastIPAddressRow) (ret error) {
	r0, _, _ := syscall.Syscall(procDeleteAnycastIpAddressEntry.Addr(), 1, uintptr(unsafe.Pointer(row)), 0, 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func deleteIPForwardEntry2(route *MibIPforwardRow2) (ret error) {
	r0, _, _ := syscall.Syscall(procDeleteIpForwardEntry2.Addr(), 1, uintptr(unsafe.Pointer(route)), 0, 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func deleteUnicastIPAddressEntry(row *MibUnicastIPAddressRow) (ret error) {
	r0, _, _ := syscall.Syscall(procDeleteUnicastIpAddressEntry.Addr(), 1, uintptr(unsafe.Pointer(row)), 0, 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func freeMibTable(memory unsafe.Pointer) {
	syscall.Syscall(procFreeMibTable.Addr(), 1, uintptr(memory), 0, 0)
	return
}

func getAnycastIPAddressEntry(row *MibAnycastIPAddressRow) (ret error) {
	r0, _, _ := syscall.Syscall(procGetAnycastIpAddressEntry.Addr(), 1, uintptr(unsafe.Pointer(row)), 0, 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func getAnycastIPAddressTable(family AddressFamily, table **mibAnycastIPAddressTable) (ret error) {
	r0, _, _ := syscall.Syscall(procGetAnycastIpAddressTable.Addr(), 2, uintptr(family), uintptr(unsafe.Pointer(table)), 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func getIfEntry2(row *MibIfRow2) (ret error) {
	r0, _, _ := syscall.Syscall(procGetIfEntry2.Addr(), 1, uintptr(unsafe.Pointer(row)), 0, 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func getIfTable2Ex(level MibIfEntryLevel, table **mibIfTable2) (ret error) {
	r0, _, _ := syscall.Syscall(procGetIfTable2Ex.Addr(), 2, uintptr(level), uintptr(unsafe.Pointer(table)), 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func getIPForwardEntry2(route *MibIPforwardRow2) (ret error) {
	r0, _, _ := syscall.Syscall(procGetIpForwardEntry2.Addr(), 1, uintptr(unsafe.Pointer(route)), 0, 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func getIPForwardTable2(family AddressFamily, table **mibIPforwardTable2) (ret error) {
	r0, _, _ := syscall.Syscall(procGetIpForwardTable2.Addr(), 2, uintptr(family), uintptr(unsafe.Pointer(table)), 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func getIPInterfaceEntry(row *MibIPInterfaceRow) (ret error) {
	r0, _, _ := syscall.Syscall(procGetIpInterfaceEntry.Addr(), 1, uintptr(unsafe.Pointer(row)), 0, 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func getIPInterfaceTable(family AddressFamily, table **mibIPInterfaceTable) (ret error) {
	r0, _, _ := syscall.Syscall(procGetIpInterfaceTable.Addr(), 2, uintptr(family), uintptr(unsafe.Pointer(table)), 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func getUnicastIPAddressEntry(row *MibUnicastIPAddressRow) (ret error) {
	r0, _, _ := syscall.Syscall(procGetUnicastIpAddressEntry.Addr(), 1, uintptr(unsafe.Pointer(row)), 0, 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func getUnicastIPAddressTable(family AddressFamily, table **mibUnicastIPAddressTable) (ret error) {
	r0, _, _ := syscall.Syscall(procGetUnicastIpAddressTable.Addr(), 2, uintptr(family), uintptr(unsafe.Pointer(table)), 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func initializeIPForwardEntry(route *MibIPforwardRow2) {
	syscall.Syscall(procInitializeIpForwardEntry.Addr(), 1, uintptr(unsafe.Pointer(route)), 0, 0)
	return
}

func initializeIPInterfaceEntry(row *MibIPInterfaceRow) {
	syscall.Syscall(procInitializeIpInterfaceEntry.Addr(), 1, uintptr(unsafe.Pointer(row)), 0, 0)
	return
}

func initializeUnicastIPAddressEntry(row *MibUnicastIPAddressRow) {
	syscall.Syscall(procInitializeUnicastIpAddressEntry.Addr(), 1, uintptr(unsafe.Pointer(row)), 0, 0)
	return
}

func notifyIPInterfaceChange(family AddressFamily, callback uintptr, callerContext uintptr, initialNotification bool, notificationHandle *windows.Handle) (ret error) {
	var _p0 uint32
	if initialNotification {
		_p0 = 1
	}
	r0, _, _ := syscall.Syscall6(procNotifyIpInterfaceChange.Addr(), 5, uintptr(family), uintptr(callback), uintptr(callerContext), uintptr(_p0), uintptr(unsafe.Pointer(notificationHandle)), 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func notifyRouteChange2(family AddressFamily, callback uintptr, callerContext uintptr, initialNotification bool, notificationHandle *windows.Handle) (ret error) {
	var _p0 uint32
	if initialNotification {
		_p0 = 1
	}
	r0, _, _ := syscall.Syscall6(procNotifyRouteChange2.Addr(), 5, uintptr(family), uintptr(callback), uintptr(callerContext), uintptr(_p0), uintptr(unsafe.Pointer(notificationHandle)), 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func notifyUnicastIPAddressChange(family AddressFamily, callback uintptr, callerContext uintptr, initialNotification bool, notificationHandle *windows.Handle) (ret error) {
	var _p0 uint32
	if initialNotification {
		_p0 = 1
	}
	r0, _, _ := syscall.Syscall6(procNotifyUnicastIpAddressChange.Addr(), 5, uintptr(family), uintptr(callback), uintptr(callerContext), uintptr(_p0), uintptr(unsafe.Pointer(notificationHandle)), 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func setInterfaceDnsSettingsByDwords(guid1 uintptr, guid2 uintptr, guid3 uintptr, guid4 uintptr, settings *DnsInterfaceSettings) (ret error) {
	ret = procSetInterfaceDnsSettings.Find()
	if ret != nil {
		return
	}
	r0, _, _ := syscall.Syscall6(procSetInterfaceDnsSettings.Addr(), 5, uintptr(guid1), uintptr(guid2), uintptr(guid3), uintptr(guid4), uintptr(unsafe.Pointer(settings)), 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func setInterfaceDnsSettingsByQwords(guid1 uintptr, guid2 uintptr, settings *DnsInterfaceSettings) (ret error) {
	ret = procSetInterfaceDnsSettings.Find()
	if ret != nil {
		return
	}
	r0, _, _ := syscall.Syscall(procSetInterfaceDnsSettings.Addr(), 3, uintptr(guid1), uintptr(guid2), uintptr(unsafe.Pointer(settings)))
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func setInterfaceDnsSettingsByPtr(guid *windows.GUID, settings *DnsInterfaceSettings) (ret error) {
	ret = procSetInterfaceDnsSettings.Find()
	if ret != nil {
		return
	}
	r0, _, _ := syscall.Syscall(procSetInterfaceDnsSettings.Addr(), 2, uintptr(unsafe.Pointer(guid)), uintptr(unsafe.Pointer(settings)), 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func setIPForwardEntry2(route *MibIPforwardRow2) (ret error) {
	r0, _, _ := syscall.Syscall(procSetIpForwardEntry2.Addr(), 1, uintptr(unsafe.Pointer(route)), 0, 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func setIPInterfaceEntry(row *MibIPInterfaceRow) (ret error) {
	r0, _, _ := syscall.Syscall(procSetIpInterfaceEntry.Addr(), 1, uintptr(unsafe.Pointer(row)), 0, 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func setUnicastIPAddressEntry(row *MibUnicastIPAddressRow) (ret error) {
	r0, _, _ := syscall.Syscall(procSetUnicastIpAddressEntry.Addr(), 1, uintptr(unsafe.Pointer(row)), 0, 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func icmpCreateFile() uintptr {
	r0, _, _ := syscall.Syscall(procIcmpCreateFile.Addr(), 0, 0, 0, 0)
	return r0
}

func icmpCloseHandle(handle uintptr) bool {
	r0, _, _ := syscall.SyscallN(procIcmpCloseHandle.Addr(), handle)
	return r0 != 0
}

func icmpSendEcho2Ex(
	icmpHandle uintptr,
	event uintptr,
	apcroutine uintptr,
	apccontext uintptr,
	sourceAddress uint32,
	destinationAddress uint32,
	requestData uintptr,
	requestSize uint16,
	option *IcmpOption,
	replyBuffer uintptr,
	replySize uint32,
	timeout uint32) (ret uint) {
	r0, _, _ := syscall.SyscallN(procIcmpSendEcho2Ex.Addr(),
		icmpHandle,
		event,
		apcroutine,
		apccontext,
		uintptr(sourceAddress),
		uintptr(destinationAddress),
		uintptr(requestData),
		uintptr(requestSize),
		uintptr(unsafe.Pointer(option)),
		replyBuffer,
		uintptr(replySize),
		uintptr(timeout),
	)

	return uint(r0)
}
