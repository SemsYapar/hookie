import hookie
import ctypes
from ctypes import wintypes
from hookie import resolve, mem

_ARGTYPES = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.LPDWORD,
    ctypes.c_void_p,
]
_RESTYPE = wintypes.BOOL
target_addr = resolve.export("kernelbase.dll", "ReadFile")

one_shot = True
def readfile_hook(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped):
    global one_shot
    bytes_read_ptr = ctypes.cast(lpNumberOfBytesRead, ctypes.POINTER(wintypes.DWORD))
    if not one_shot:
        bytes_read_ptr.contents.value = 0
        return True
    one_shot = False
    new_buffer = b"this is a hooked text"
    # lpBuffer is the caller's output buffer (already writable), so no page-
    # protection flip is needed — mem.write_bytes(..., protect=False).
    mem.write_bytes(lpBuffer, new_buffer, protect=False)
    bytes_read_ptr.contents.value = len(new_buffer)
    return True

engine = hookie.HookEngine()
hook = engine.create_hook(target_addr, readfile_hook, _ARGTYPES, _RESTYPE)

if __name__ == "__main__":
    target_file = "test.txt"

    with open(target_file, "w") as f:
        f.write("this is a non hooked text.")

    with open(target_file, "r") as f:
        data = f.read()
        print("test.txt data original: "+data)
        hook.enable()
        data = f.read()
        print("test.txt data hooked: "+data)
        hook.disable()
