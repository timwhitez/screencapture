// Code generated by 'go generate'; DO NOT EDIT.

package win

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
	modGdi32    = windows.NewLazySystemDLL("Gdi32.dll")
	modKernel32 = windows.NewLazySystemDLL("Kernel32.dll")
	modShell32  = windows.NewLazySystemDLL("Shell32.dll")
	modUser32   = windows.NewLazySystemDLL("User32.dll")

	procGetCurrentObject              = modGdi32.NewProc("GetCurrentObject")
	procGetDIBits                     = modGdi32.NewProc("GetDIBits")
	procGetProcessHeap                = modKernel32.NewProc("GetProcessHeap")
	procHeapAlloc                     = modKernel32.NewProc("HeapAlloc")
	procHeapFree                      = modKernel32.NewProc("HeapFree")
	procHeapSize                      = modKernel32.NewProc("HeapSize")
	procDragQueryFileW                = modShell32.NewProc("DragQueryFileW")
	procAddClipboardFormatListener    = modUser32.NewProc("AddClipboardFormatListener")
	procCloseClipboard                = modUser32.NewProc("CloseClipboard")
	procEmptyClipboard                = modUser32.NewProc("EmptyClipboard")
	procEnumClipboardFormats          = modUser32.NewProc("EnumClipboardFormats")
	procGetClipboardData              = modUser32.NewProc("GetClipboardData")
	procGetClipboardFormatNameW       = modUser32.NewProc("GetClipboardFormatNameW")
	procGetDesktopWindow              = modUser32.NewProc("GetDesktopWindow")
	procIsClipboardFormatAvailable    = modUser32.NewProc("IsClipboardFormatAvailable")
	procIsValidDpiAwarenessContext    = modUser32.NewProc("IsValidDpiAwarenessContext")
	procOpenClipboard                 = modUser32.NewProc("OpenClipboard")
	procRegisterClipboardFormatW      = modUser32.NewProc("RegisterClipboardFormatW")
	procRemoveClipboardFormatListener = modUser32.NewProc("RemoveClipboardFormatListener")
	procSetClipboardData              = modUser32.NewProc("SetClipboardData")
	procSetThreadDpiAwarenessContext  = modUser32.NewProc("SetThreadDpiAwarenessContext")
	procSetWindowsHookExW             = modUser32.NewProc("SetWindowsHookExW")
)

func GetCurrentObject(hdc syscall.Handle, typ uint16) (h syscall.Handle) {
	r0, _, _ := syscall.Syscall(procGetCurrentObject.Addr(), 2, uintptr(hdc), uintptr(typ), 0)
	h = syscall.Handle(r0)
	return
}

func GetDIBits(hdc syscall.Handle, hbmp syscall.Handle, uStartScan uint32, cScanLines uint32, lpvBits *byte, lpbi *BITMAPINFO, uUsage uint32) (v int32, err error) {
	r0, _, e1 := syscall.Syscall9(procGetDIBits.Addr(), 7, uintptr(hdc), uintptr(hbmp), uintptr(uStartScan), uintptr(cScanLines), uintptr(unsafe.Pointer(lpvBits)), uintptr(unsafe.Pointer(lpbi)), uintptr(uUsage), 0, 0)
	v = int32(r0)
	if v == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetProcessHeap() (hHeap syscall.Handle, err error) {
	r0, _, e1 := syscall.Syscall(procGetProcessHeap.Addr(), 0, 0, 0, 0)
	hHeap = syscall.Handle(r0)
	if hHeap == 0 {
		err = errnoErr(e1)
	}
	return
}

func HeapAlloc(hHeap syscall.Handle, dwFlags uint32, dwSize uintptr) (lpMem uintptr, err error) {
	r0, _, e1 := syscall.Syscall(procHeapAlloc.Addr(), 3, uintptr(hHeap), uintptr(dwFlags), uintptr(dwSize))
	lpMem = uintptr(r0)
	if lpMem == 0 {
		err = errnoErr(e1)
	}
	return
}

func HeapFree(hHeap syscall.Handle, dwFlags uint32, lpMem uintptr) (err error) {
	r1, _, e1 := syscall.Syscall(procHeapFree.Addr(), 3, uintptr(hHeap), uintptr(dwFlags), uintptr(lpMem))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func heapSize(hHeap syscall.Handle, dwFlags uint32, lpMem uintptr) (size uintptr, err error) {
	r0, _, e1 := syscall.Syscall(procHeapSize.Addr(), 3, uintptr(hHeap), uintptr(dwFlags), uintptr(lpMem))
	size = uintptr(r0)
	if size == ^uintptr(r0) {
		err = errnoErr(e1)
	}
	return
}

func dragQueryFile(hDrop syscall.Handle, iFile int, buf *uint16, len uint32) (n int, err error) {
	r0, _, e1 := syscall.Syscall6(procDragQueryFileW.Addr(), 4, uintptr(hDrop), uintptr(iFile), uintptr(unsafe.Pointer(buf)), uintptr(len), 0, 0)
	n = int(r0)
	if n == 0 {
		err = errnoErr(e1)
	}
	return
}

func AddClipboardFormatListener(hWnd syscall.Handle) (err error) {
	r1, _, e1 := syscall.Syscall(procAddClipboardFormatListener.Addr(), 1, uintptr(hWnd), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func closeClipboard() (err error) {
	r1, _, e1 := syscall.Syscall(procCloseClipboard.Addr(), 0, 0, 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func emptyClipboard() (err error) {
	r1, _, e1 := syscall.Syscall(procEmptyClipboard.Addr(), 0, 0, 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func enumClipboardFormats(format uint32) (id uint32, err error) {
	r0, _, e1 := syscall.Syscall(procEnumClipboardFormats.Addr(), 1, uintptr(format), 0, 0)
	id = uint32(r0)
	if id == 0 {
		err = errnoErr(e1)
	}
	return
}

func getClipboardData(uFormat uint32) (h syscall.Handle, err error) {
	r0, _, e1 := syscall.Syscall(procGetClipboardData.Addr(), 1, uintptr(uFormat), 0, 0)
	h = syscall.Handle(r0)
	if h == 0 {
		err = errnoErr(e1)
	}
	return
}

func getClipboardFormatName(format uint32, lpszFormatName *uint16, cchMaxCount int32) (len int32, err error) {
	r0, _, e1 := syscall.Syscall(procGetClipboardFormatNameW.Addr(), 3, uintptr(format), uintptr(unsafe.Pointer(lpszFormatName)), uintptr(cchMaxCount))
	len = int32(r0)
	if len == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetDesktopWindow() (h HWND) {
	r0, _, _ := syscall.Syscall(procGetDesktopWindow.Addr(), 0, 0, 0, 0)
	h = HWND(r0)
	return
}

func isClipboardFormatAvailable(uFormat uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procIsClipboardFormatAvailable.Addr(), 1, uintptr(uFormat), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func IsValidDpiAwarenessContext(value int32) (n bool) {
	r0, _, _ := syscall.Syscall(procIsValidDpiAwarenessContext.Addr(), 1, uintptr(value), 0, 0)
	n = r0 != 0
	return
}

func openClipboard(h syscall.Handle) (err error) {
	r1, _, e1 := syscall.Syscall(procOpenClipboard.Addr(), 1, uintptr(h), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func registerClipboardFormat(name string) (id uint32, err error) {
	var _p0 *uint16
	_p0, err = syscall.UTF16PtrFromString(name)
	if err != nil {
		return
	}
	return _registerClipboardFormat(_p0)
}

func _registerClipboardFormat(name *uint16) (id uint32, err error) {
	r0, _, e1 := syscall.Syscall(procRegisterClipboardFormatW.Addr(), 1, uintptr(unsafe.Pointer(name)), 0, 0)
	id = uint32(r0)
	if id == 0 {
		err = errnoErr(e1)
	}
	return
}

func RemoveClipboardFormatListener(hWnd syscall.Handle) (err error) {
	r1, _, e1 := syscall.Syscall(procRemoveClipboardFormatListener.Addr(), 1, uintptr(hWnd), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func setClipboardData(uFormat uint32, hMem syscall.Handle) (h syscall.Handle, err error) {
	r0, _, e1 := syscall.Syscall(procSetClipboardData.Addr(), 2, uintptr(uFormat), uintptr(hMem), 0)
	h = syscall.Handle(r0)
	if h == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetThreadDpiAwarenessContext(value int32) (n int, err error) {
	r0, _, e1 := syscall.Syscall(procSetThreadDpiAwarenessContext.Addr(), 1, uintptr(value), 0, 0)
	n = int(r0)
	if n == 0 {
		err = errnoErr(e1)
	}
	return
}

func setWindowsHookExW(idHook int32, lpfn unsafe.Pointer, hmod syscall.Handle, dwThreadId uint32) (h syscall.Handle, err error) {
	r0, _, e1 := syscall.Syscall6(procSetWindowsHookExW.Addr(), 4, uintptr(idHook), uintptr(lpfn), uintptr(hmod), uintptr(dwThreadId), 0, 0)
	h = syscall.Handle(r0)
	if h == 0 {
		err = errnoErr(e1)
	}
	return
}
