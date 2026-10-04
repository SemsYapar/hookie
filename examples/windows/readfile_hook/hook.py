import hookie
import ctypes
from ctypes import wintypes

kernelbase = ctypes.windll.kernelbase
kernelbase.ReadFile.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.LPDWORD,
    ctypes.c_void_p
]
kernelbase.ReadFile.restype = wintypes.BOOL
target_addr = ctypes.cast(kernelbase.ReadFile, ctypes.c_void_p).value

one_shot = True
def readfile_hook(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped):
    global one_shot
    bytes_read_ptr = ctypes.cast(lpNumberOfBytesRead, ctypes.POINTER(wintypes.DWORD))  
    if not one_shot:
        bytes_read_ptr.contents.value = 0
        return True
    one_shot = False
    new_buffer = b"this is a hooked text"
    buf_len = len(new_buffer)   
    new_buffer = ctypes.create_string_buffer(new_buffer)
    ctypes.memmove(lpBuffer, new_buffer, buf_len)
    bytes_read_ptr.contents.value = buf_len
    return True

engine = hookie.HookEngine()
hook = engine.create_hook(target_addr, readfile_hook, kernelbase.ReadFile.argtypes, kernelbase.ReadFile.restype)

if __name__ == "__main__":
    target_file = "test.txt"

    with open(target_file, "w") as f:
        f.write("this is a non hooked text.")

    with open(target_file, "r") as f:
        hook.enable()
        data = f.read()
        hook.disable()
        print("test.txt data: "+data)