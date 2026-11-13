import hookie
import ctypes
from ctypes import wintypes

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

kernelbase = ctypes.windll.kernelbase
ntdll = ctypes.windll.ntdll
psapi = ctypes.windll.psapi

kernelbase.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
kernelbase.TerminateProcess.restype = wintypes.BOOL

kernelbase.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernelbase.OpenProcess.restype = wintypes.HANDLE

psapi.GetModuleBaseNameW.argtypes = [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
psapi.GetModuleBaseNameW.restype = wintypes.DWORD

def get_pid_from_handle(h_process):
  class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Reserved1", ctypes.c_void_p),
        ("PebBaseAddress", ctypes.c_void_p),
        ("Reserved2", ctypes.c_void_p * 2),
        ("UniqueProcessId", ctypes.c_void_p),
        ("Reserved3", ctypes.c_void_p),
    ]

  pbi = PROCESS_BASIC_INFORMATION()
  return_length = ctypes.c_ulong()

  # Mevcut handle üzerinden PID'yi sorgula (ProcessBasicInformation = 0)
  status = ntdll.NtQueryInformationProcess(
      h_process, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(return_length)
  )

  if status == 0:
    return int(pbi.UniqueProcessId)
  return None

def terminateprocess_hook(hProcess, uExitCode):
    buf_size = 260
    buf = ctypes.create_unicode_buffer(buf_size)
    pid = get_pid_from_handle(hProcess)
    hRead = kernelbase.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if psapi.GetModuleBaseNameW(hRead, None, buf, buf_size) and buf.value == "chrome.exe":
        return 1
    else:
        return hook.original(hProcess, uExitCode)

target_addr = ctypes.cast(kernelbase.TerminateProcess, ctypes.c_void_p).value
engine = hookie.HookEngine()
hook = engine.create_hook(target_addr, terminateprocess_hook, kernelbase.TerminateProcess.argtypes, kernelbase.TerminateProcess.restype)
hook.enable()