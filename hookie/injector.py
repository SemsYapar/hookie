"""Minimal Windows LoadLibraryW injector for hookie smoke tests."""
from __future__ import annotations

import ctypes
import os
import sys
from ctypes import wintypes
from pathlib import Path


def _windows_only() -> None:
    if os.name != "nt":
        raise RuntimeError("inject-dll is available on Windows only")


def _pid_from_name(name: str) -> int:
    _windows_only()
    TH32CS_SNAPPROCESS = 0x00000002
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260),
        ]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k32.Process32FirstW.argtypes = (wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W))
    k32.Process32FirstW.restype = wintypes.BOOL
    k32.Process32NextW.argtypes = (wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W))
    k32.Process32NextW.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = (wintypes.HANDLE,)

    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        ok = k32.Process32FirstW(snap, ctypes.byref(entry))
        wanted = name.casefold()
        matches: list[int] = []
        while ok:
            if entry.szExeFile.casefold() == wanted:
                matches.append(int(entry.th32ProcessID))
            ok = k32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        k32.CloseHandle(snap)

    if not matches:
        raise ProcessLookupError(f"process not found: {name}")
    if len(matches) != 1:
        raise RuntimeError(f"multiple processes named {name!r}: {matches}; use a PID")
    return matches[0]


def inject_dll(target: str, dll: Path, *, timeout_ms: int = 15_000) -> int | None:
    """Inject *dll* into a Windows process using LoadLibraryW; return thread exit code."""
    _windows_only()
    dll = dll.expanduser().resolve(strict=True)
    if dll.suffix.casefold() != ".dll":
        raise ValueError(f"expected a .dll file: {dll}")
    pid = int(target) if target.isdecimal() else _pid_from_name(target)

    PROCESS_CREATE_THREAD = 0x0002
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_OPERATION = 0x0008
    PROCESS_VM_WRITE = 0x0020
    PROCESS_VM_READ = 0x0010
    rights = (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
              PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)
    MEM_COMMIT, MEM_RESERVE, MEM_RELEASE = 0x1000, 0x2000, 0x8000
    PAGE_READWRITE = 0x04
    WAIT_OBJECT_0 = 0x00000000
    WAIT_TIMEOUT = 0x00000102

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.VirtualAllocEx.argtypes = (wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
                                   wintypes.DWORD, wintypes.DWORD)
    k32.VirtualAllocEx.restype = ctypes.c_void_p
    k32.WriteProcessMemory.argtypes = (wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                       ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t))
    k32.WriteProcessMemory.restype = wintypes.BOOL
    k32.GetModuleHandleW.argtypes = (wintypes.LPCWSTR,)
    k32.GetModuleHandleW.restype = wintypes.HMODULE
    k32.GetProcAddress.argtypes = (wintypes.HMODULE, ctypes.c_char_p)
    k32.GetProcAddress.restype = ctypes.c_void_p
    k32.CreateRemoteThread.argtypes = (wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
                                       ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD,
                                       ctypes.POINTER(wintypes.DWORD))
    k32.CreateRemoteThread.restype = wintypes.HANDLE
    k32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    k32.WaitForSingleObject.restype = wintypes.DWORD
    k32.GetExitCodeThread.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
    k32.GetExitCodeThread.restype = wintypes.BOOL
    k32.VirtualFreeEx.argtypes = (wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD)
    k32.VirtualFreeEx.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = (wintypes.HANDLE,)

    process = k32.OpenProcess(rights, False, pid)
    if not process:
        raise ctypes.WinError(ctypes.get_last_error())
    remote = None
    thread = None
    remote_still_in_use = False
    try:
        raw = (str(dll) + "\0").encode("utf-16-le")
        remote = k32.VirtualAllocEx(process, None, len(raw), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if not remote:
            raise ctypes.WinError(ctypes.get_last_error())
        buf = ctypes.create_string_buffer(raw)
        written = ctypes.c_size_t()
        if not k32.WriteProcessMemory(process, remote, buf, len(raw), ctypes.byref(written)):
            raise ctypes.WinError(ctypes.get_last_error())
        if written.value != len(raw):
            raise OSError(f"short WriteProcessMemory: {written.value}/{len(raw)}")

        kernel32 = k32.GetModuleHandleW("kernel32.dll")
        load_library = k32.GetProcAddress(kernel32, b"LoadLibraryW")
        if not load_library:
            raise ctypes.WinError(ctypes.get_last_error())
        thread = k32.CreateRemoteThread(process, None, 0, load_library, remote, 0, None)
        if not thread:
            raise ctypes.WinError(ctypes.get_last_error())
        wait = k32.WaitForSingleObject(thread, timeout_ms)
        if wait == WAIT_TIMEOUT:
            # The target may simply be suspended in a debugger.  The remote
            # thread can still consume the DLL path after we return, so do not
            # free that allocation here.  Closing our handles is safe; Windows
            # keeps the underlying process/thread objects alive as needed.
            remote_still_in_use = True
            return None
        if wait != WAIT_OBJECT_0:
            raise OSError(f"WaitForSingleObject failed/unexpected result: 0x{wait:08x}")
        code = wintypes.DWORD()
        if not k32.GetExitCodeThread(thread, ctypes.byref(code)):
            raise ctypes.WinError(ctypes.get_last_error())
        if code.value == 0:
            raise OSError("remote LoadLibraryW failed (thread exit code 0)")
        return int(code.value)
    finally:
        if thread:
            k32.CloseHandle(thread)
        if remote and not remote_still_in_use:
            k32.VirtualFreeEx(process, remote, 0, MEM_RELEASE)
        k32.CloseHandle(process)
