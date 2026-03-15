//go:build windows

package tun

import (
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	th32csSnapProcess = 0x00000002
)

var (
	kernel32DLL                    = windows.NewLazySystemDLL("kernel32.dll")
	procCreateToolhelp32Snapshot   = kernel32DLL.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW            = kernel32DLL.NewProc("Process32FirstW")
	procProcess32NextW             = kernel32DLL.NewProc("Process32NextW")
	procQueryFullProcessImageNameW = kernel32DLL.NewProc("QueryFullProcessImageNameW")
)

type processEntry32 struct {
	Size              uint32
	Usage             uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	Threads           uint32
	ParentProcessID   uint32
	PriClassBase      int32
	Flags             uint32
	ExeFile           [windows.MAX_PATH]uint16
}

func normalizeProcessName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	return strings.ToLower(filepath.Base(name))
}

func normalizeProcessPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if absPath, err := filepath.Abs(path); err == nil {
		path = absPath
	}
	return strings.ToLower(filepath.Clean(path))
}

func getExecPathFromPID(pid uint32) (string, error) {
	switch pid {
	case 0:
		return ":System Idle Process", nil
	case 4:
		return ":System", nil
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, syscall.MAX_LONG_PATH)
	size := uint32(len(buf))
	r1, _, err := procQueryFullProcessImageNameW.Call(
		uintptr(h),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if r1 == 0 {
		if err != syscall.Errno(0) {
			return "", err
		}
		return "", windows.ERROR_INVALID_DATA
	}
	return syscall.UTF16ToString(buf[:size]), nil
}

func resolveExcludedProcessPaths(names []string, paths []string) ([]string, []string, error) {
	resolved := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		normalized := normalizeProcessPath(path)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		resolved = append(resolved, normalized)
	}

	nameSet := make(map[string]struct{}, len(names))
	for _, name := range names {
		normalized := normalizeProcessName(name)
		if normalized != "" {
			nameSet[normalized] = struct{}{}
		}
	}
	if len(nameSet) == 0 {
		return resolved, nil, nil
	}

	snapshot, err := createToolhelp32Snapshot(th32csSnapProcess, 0)
	if err != nil {
		return resolved, nil, err
	}
	defer windows.CloseHandle(snapshot)

	entry := processEntry32{Size: uint32(unsafe.Sizeof(processEntry32{}))}
	ok, err := process32First(snapshot, &entry)
	if err != nil {
		return resolved, nil, err
	}
	foundNames := make(map[string]struct{}, len(nameSet))
	for ok {
		name := normalizeProcessName(windows.UTF16ToString(entry.ExeFile[:]))
		if _, matched := nameSet[name]; matched {
			path, pathErr := getExecPathFromPID(entry.ProcessID)
			if pathErr == nil {
				normalizedPath := normalizeProcessPath(path)
				if normalizedPath != "" {
					if _, exists := seen[normalizedPath]; !exists {
						seen[normalizedPath] = struct{}{}
						resolved = append(resolved, normalizedPath)
					}
					foundNames[name] = struct{}{}
				}
			}
		}
		entry.Size = uint32(unsafe.Sizeof(processEntry32{}))
		ok, err = process32Next(snapshot, &entry)
		if err != nil {
			return resolved, nil, err
		}
	}

	unresolved := make([]string, 0, len(nameSet))
	for name := range nameSet {
		if _, ok := foundNames[name]; !ok {
			unresolved = append(unresolved, name)
		}
	}
	return resolved, unresolved, nil
}

func createToolhelp32Snapshot(flags uint32, processID uint32) (windows.Handle, error) {
	r1, _, err := procCreateToolhelp32Snapshot.Call(uintptr(flags), uintptr(processID))
	handle := windows.Handle(r1)
	if handle == windows.InvalidHandle {
		if err != syscall.Errno(0) {
			return 0, err
		}
		return 0, windows.ERROR_INVALID_HANDLE
	}
	return handle, nil
}

func process32First(snapshot windows.Handle, entry *processEntry32) (bool, error) {
	r1, _, err := procProcess32FirstW.Call(uintptr(snapshot), uintptr(unsafe.Pointer(entry)))
	if r1 == 0 {
		if err == syscall.ERROR_NO_MORE_FILES {
			return false, nil
		}
		if err != syscall.Errno(0) {
			return false, err
		}
		return false, windows.ERROR_NOT_FOUND
	}
	return true, nil
}

func process32Next(snapshot windows.Handle, entry *processEntry32) (bool, error) {
	r1, _, err := procProcess32NextW.Call(uintptr(snapshot), uintptr(unsafe.Pointer(entry)))
	if r1 == 0 {
		if err == syscall.ERROR_NO_MORE_FILES {
			return false, nil
		}
		if err != syscall.Errno(0) {
			return false, err
		}
		return false, windows.ERROR_NOT_FOUND
	}
	return true, nil
}

func processFilterDescription(path string) string {
	base := filepath.Base(path)
	if base == "." || base == string(filepath.Separator) || base == "" {
		return path
	}
	return fmt.Sprintf("exclude %s", base)
}
