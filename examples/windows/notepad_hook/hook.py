import hookie
import ctypes
from ctypes import wintypes
import os

kernelbase = ctypes.windll.kernelbase

VOLUME_NAME_DOS = 0x0
PAGE_WRITECOPY = 0x08
FILE_MAP_COPY = 0x0001

kernelbase.GetFinalPathNameByHandleW.argtypes = [
    wintypes.HANDLE,
    wintypes.LPWSTR,
    wintypes.DWORD,
    wintypes.DWORD
]
kernelbase.GetFinalPathNameByHandleW.restype = wintypes.DWORD

kernelbase.MapViewOfFile.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.c_size_t
]

kernelbase.MapViewOfFile.restype = ctypes.c_void_p

kernelbase.CreateFileMappingW.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPCWSTR
]

kernelbase.CreateFileMappingW.restype = wintypes.HANDLE

def get_filename_from_handle(h_file: int):
    buf_size = kernelbase.GetFinalPathNameByHandleW(h_file, None, 0, VOLUME_NAME_DOS)
    if buf_size == 0:
        return 1
    
    buf = ctypes.create_unicode_buffer(buf_size)
    if kernelbase.GetFinalPathNameByHandleW(h_file, buf, buf_size, VOLUME_NAME_DOS) == 0:
        return 2

    full_path = buf.value
    return os.path.basename(full_path)

sHandle_to_filename = {}

def createfilemappingw_hook(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName):
    filename = get_filename_from_handle(hFile)

    if filename == 1 or filename == 2 or filename[-4:] != ".txt":
        return hook2.original(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName)

    sHandle = hook2.original(hFile, lpFileMappingAttributes, PAGE_WRITECOPY, dwMaximumSizeHigh, dwMaximumSizeLow, lpName)

    if sHandle:
        sHandle_to_filename[sHandle] = filename

    return sHandle

def mapviewoffile_hook(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap):
    if hFileMappingObject in sHandle_to_filename:
        if sHandle_to_filename[hFileMappingObject][-4:] == ".txt":
            data_ptr = hook.original(hFileMappingObject, FILE_MAP_COPY, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap)

            if not data_ptr:
                return data_ptr

            new_buffer = b"hooked by hookie"
            buf_len = len(new_buffer)
            new_buffer = ctypes.create_string_buffer(new_buffer)

            if dwNumberOfBytesToMap >= buf_len:
                ctypes.memset(data_ptr, 0, dwNumberOfBytesToMap)
                ctypes.memmove(data_ptr, new_buffer, buf_len)

            return data_ptr
        
    data_ptr = hook.original(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap)
    return data_ptr

target_addr = ctypes.cast(kernelbase.MapViewOfFile, ctypes.c_void_p).value
engine = hookie.HookEngine()
hook = engine.create_hook(target_addr, mapviewoffile_hook, kernelbase.MapViewOfFile.argtypes, kernelbase.MapViewOfFile.restype)
hook.enable()

target_addr2 = ctypes.cast(kernelbase.CreateFileMappingW, ctypes.c_void_p).value
hook2 = engine.create_hook(target_addr2, createfilemappingw_hook, kernelbase.CreateFileMappingW.argtypes, kernelbase.CreateFileMappingW.restype)
hook2.enable()