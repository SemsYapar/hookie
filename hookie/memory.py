import ctypes
import ctypes.util
import os
import sys

IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    PAGE_NOACCESS = 0x01
    PAGE_READONLY = 0x02
    PAGE_READWRITE = 0x04
    PAGE_WRITECOPY = 0x08
    PAGE_EXECUTE = 0x10
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_WRITECOPY = 0x80
    PAGE_GUARD = 0x100
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    MEM_RELEASE = 0x8000
    MEM_FREE = 0x10000

    class SYSTEM_INFO(ctypes.Structure):
        _fields_ = [
            ("wProcessorArchitecture", ctypes.c_ushort),
            ("wReserved", ctypes.c_ushort),
            ("dwPageSize", ctypes.c_ulong),
            ("lpMinimumApplicationAddress", ctypes.c_void_p),
            ("lpMaximumApplicationAddress", ctypes.c_void_p),
            ("dwActiveProcessorMask", ctypes.c_size_t),
            ("dwNumberOfProcessors", ctypes.c_ulong),
            ("dwProcessorType", ctypes.c_ulong),
            ("dwAllocationGranularity", ctypes.c_ulong),
            ("wProcessorLevel", ctypes.c_ushort),
            ("wProcessorRevision", ctypes.c_ushort),
        ]

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", ctypes.c_ulong),
            ("PartitionId", ctypes.c_ushort),
            ("RegionSize", ctypes.c_size_t),
            ("State", ctypes.c_ulong),
            ("Protect", ctypes.c_ulong),
            ("Type", ctypes.c_ulong),
        ]

    kernel32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    kernel32.VirtualProtect.restype = ctypes.c_int
    kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
    kernel32.VirtualAlloc.restype = ctypes.c_void_p
    kernel32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]
    kernel32.VirtualFree.restype = ctypes.c_int
    kernel32.VirtualQuery.argtypes = [ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
    kernel32.VirtualQuery.restype = ctypes.c_size_t
    kernel32.GetSystemInfo.argtypes = [ctypes.POINTER(SYSTEM_INFO)]
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.FlushInstructionCache.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    kernel32.FlushInstructionCache.restype = ctypes.c_int
else:
    libc_path = ctypes.util.find_library("c")
    if not libc_path:
        raise RuntimeError("libc not found")
    libc = ctypes.CDLL(libc_path, use_errno=True)
    PROT_READ, PROT_WRITE, PROT_EXEC = 1, 2, 4
    MAP_PRIVATE, MAP_ANONYMOUS = 0x02, 0x20
    MAP_FIXED_NOREPLACE = 0x100000
    MAP_FAILED = ctypes.c_void_p(-1).value
    libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    libc.mprotect.restype = ctypes.c_int
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
    libc.mmap.restype = ctypes.c_void_p
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    libc.munmap.restype = ctypes.c_int


class MemoryManager:
    @staticmethod
    def _page_size() -> int:
        if IS_WINDOWS:
            si = SYSTEM_INFO(); kernel32.GetSystemInfo(ctypes.byref(si)); return si.dwPageSize
        return os.sysconf("SC_PAGE_SIZE")

    @staticmethod
    def _align_down(v: int, a: int) -> int:
        return v & ~(a - 1)

    @staticmethod
    def _align_up(v: int, a: int) -> int:
        return (v + a - 1) & ~(a - 1)

    @staticmethod
    def _linux_region_prot(address: int) -> int:
        """mprotect eski korumayı döndürmez; o yüzden değiştirmeden önce bu
        adresi içeren mapping'in mevcut iznini /proc/self/maps'ten okuyup
        PROT_* bayraklarına çeviririz. Mapping doğrulanamazsa tahmin etmek
        yerine hata veririz; yanlış izinle restore etmek güvenli değildir."""
        try:
            with open("/proc/self/maps", "r", encoding="ascii", errors="replace") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    a, b = parts[0].split("-")
                    if int(a, 16) <= address < int(b, 16):
                        perms = parts[1]
                        prot = 0
                        if perms[0] == "r": prot |= PROT_READ
                        if perms[1] == "w": prot |= PROT_WRITE
                        if perms[2] == "x": prot |= PROT_EXEC
                        return prot
        except OSError as exc:
            raise OSError("cannot read /proc/self/maps to determine page protection") from exc
        raise OSError(f"address 0x{address:X} is not present in /proc/self/maps")

    @staticmethod
    def make_rwx(address: int, size: int) -> int | None:
        if address <= 0 or size <= 0:
            raise ValueError("invalid address/size")
        if IS_WINDOWS:
            old = ctypes.c_ulong()
            if not kernel32.VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, ctypes.byref(old)):
                raise OSError(ctypes.get_last_error(), "VirtualProtect failed")
            return old.value
        # Değiştirmeden ÖNCE mevcut korumayı sakla; restore_protection geri yazar.
        old_prot = MemoryManager._linux_region_prot(address)
        page = MemoryManager._page_size()
        start = MemoryManager._align_down(address, page)
        end = MemoryManager._align_up(address + size, page)
        if libc.mprotect(start, end - start, PROT_READ | PROT_WRITE | PROT_EXEC) != 0:
            e = ctypes.get_errno(); raise OSError(e, os.strerror(e))
        return old_prot

    @staticmethod
    def restore_protection(address: int, size: int, old_protect: int | None) -> None:
        if old_protect is None:
            return
        if IS_WINDOWS:
            ignored = ctypes.c_ulong()
            if not kernel32.VirtualProtect(address, size, old_protect, ctypes.byref(ignored)):
                raise OSError(ctypes.get_last_error(), "VirtualProtect restore failed")
            return
        # Linux: W^X'e saygı için sayfayı orijinal korumasına (genelde R-X) döndür.
        page = MemoryManager._page_size()
        start = MemoryManager._align_down(address, page)
        end = MemoryManager._align_up(address + size, page)
        if libc.mprotect(start, end - start, old_protect) != 0:
            e = ctypes.get_errno(); raise OSError(e, os.strerror(e))

    @staticmethod
    def allocate_rw(size: int = 4096) -> int:
        if size <= 0:
            raise ValueError("size must be greater than zero")
        if IS_WINDOWS:
            p = kernel32.VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
            if not p:
                raise OSError(ctypes.get_last_error(), "VirtualAlloc failed")
            return int(p)
        p = libc.mmap(None, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
        if p is None or p == MAP_FAILED:
            e = ctypes.get_errno(); raise OSError(e, os.strerror(e))
        return int(p)

    @staticmethod
    def protect_rx(address: int, size: int) -> None:
        """W^X: executable memory is allocated RW, written, then flipped to R-X
        here. Nothing hookie allocates stays writable+executable simultaneously,
        so hardened systems that reject WX mappings keep working."""
        if address <= 0 or size <= 0:
            raise ValueError("invalid address/size")
        if IS_WINDOWS:
            old = ctypes.c_ulong()
            if not kernel32.VirtualProtect(address, size, PAGE_EXECUTE_READ, ctypes.byref(old)):
                raise OSError(ctypes.get_last_error(), "VirtualProtect(RX) failed")
            return
        page = MemoryManager._page_size()
        start = MemoryManager._align_down(address, page)
        end = MemoryManager._align_up(address + size, page)
        if libc.mprotect(start, end - start, PROT_READ | PROT_EXEC) != 0:
            e = ctypes.get_errno(); raise OSError(e, os.strerror(e))

    @staticmethod
    def readable_extent(address: int, want: int) -> int:
        """Bytes safely readable from *address*, capped at *want*. Prevents a
        fixed-size prologue read from running off the end of a mapping into an
        unmapped/guard page and faulting the whole process."""
        if address <= 0 or want <= 0:
            raise ValueError("invalid address/want")
        if IS_WINDOWS:
            mbi = MEMORY_BASIC_INFORMATION()
            if not kernel32.VirtualQuery(address, ctypes.byref(mbi), ctypes.sizeof(mbi)):
                return 0
            readable = (PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
                        PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY)
            if mbi.State != MEM_COMMIT or (mbi.Protect & PAGE_GUARD) or (mbi.Protect & 0xFF) not in readable:
                return 0
            region_end = int(mbi.BaseAddress or 0) + int(mbi.RegionSize)
            return max(0, min(want, region_end - address))
        try:
            with open("/proc/self/maps", "r", encoding="ascii", errors="replace") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    a, b = parts[0].split("-")
                    lo, hi = int(a, 16), int(b, 16)
                    if lo <= address < hi:
                        if parts[1][0] != "r":
                            return 0
                        return min(want, hi - address)
        except OSError:
            return 0
        return 0

    @staticmethod
    def allocate_near(size: int, low: int, high: int) -> int | None:
        """Allocate a block wholly inside [low, high]."""
        if size <= 0:
            raise ValueError("size must be greater than zero")
        if high < low or high - low + 1 < size:
            return None
        return MemoryManager._allocate_near_windows(size, low, high) if IS_WINDOWS else MemoryManager._allocate_near_linux(size, low, high)

    @staticmethod
    def _allocate_near_windows(size: int, low: int, high: int) -> int | None:
        si = SYSTEM_INFO(); kernel32.GetSystemInfo(ctypes.byref(si))
        gran = si.dwAllocationGranularity
        lo = max(low, int(si.lpMinimumApplicationAddress or 0))
        hi = min(high, int(si.lpMaximumApplicationAddress or 0))
        last_base = hi - size + 1
        if last_base < lo:
            return None
        center = (lo + last_base) // 2
        # VirtualQuery walk; collect free regions, then try nearest candidates.
        regions = []
        p = lo
        mbi = MEMORY_BASIC_INFORMATION()
        while p <= last_base:
            n = kernel32.VirtualQuery(p, ctypes.byref(mbi), ctypes.sizeof(mbi))
            if not n:
                p += gran; continue
            base = int(mbi.BaseAddress or 0); end = base + int(mbi.RegionSize)
            if mbi.State == MEM_FREE:
                a = max(lo, base); b = min(last_base, end - size)
                if a <= b:
                    cand = min(max(center, a), b)
                    cand = MemoryManager._align_down(cand, gran)
                    if cand < a: cand = MemoryManager._align_up(a, gran)
                    if cand <= b: regions.append(cand)
            p = max(p + gran, end)
        regions.sort(key=lambda x: abs(x - center))
        for cand in regions:
            p = kernel32.VirtualAlloc(cand, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
            if p:
                return int(p)
        return None

    @staticmethod
    def _allocate_near_linux(size: int, low: int, high: int) -> int | None:
        page = MemoryManager._page_size()
        lo = MemoryManager._align_up(max(0, low), page)
        last = MemoryManager._align_down(high - size + 1, page)
        if last < lo:
            return None
        mapped = []
        with open("/proc/self/maps", "r", encoding="ascii", errors="replace") as f:
            for line in f:
                rng = line.split(None, 1)[0]
                a, b = rng.split("-")
                mapped.append((int(a, 16), int(b, 16)))
        mapped.sort()
        gaps = []
        cursor = lo
        for a, b in mapped:
            if b <= lo: continue
            if a > high: break
            if cursor + size <= min(a, high + 1): gaps.append((cursor, min(a, high + 1)))
            cursor = max(cursor, b)
        if cursor + size <= high + 1: gaps.append((cursor, high + 1))
        center = (lo + last) // 2
        candidates = []
        for a, b in gaps:
            min_base = MemoryManager._align_up(a, page)
            max_base = MemoryManager._align_down(b - size, page)
            if min_base <= max_base:
                cand = min(max(center, min_base), max_base)
                cand = MemoryManager._align_down(cand, page)
                candidates.append(cand)
        candidates.sort(key=lambda x: abs(x - center))
        flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE
        for cand in candidates:
            p = libc.mmap(cand, size, PROT_READ | PROT_WRITE, flags, -1, 0)
            if p is None or p == MAP_FAILED:
                continue
            p = int(p)
            if p != cand:  # old kernel may ignore MAP_FIXED_NOREPLACE
                libc.munmap(p, size)
                continue
            return p
        return None

    @staticmethod
    def free_rwx(address: int, size: int = 4096) -> None:
        if address <= 0 or size <= 0:
            raise ValueError("invalid address/size")
        if IS_WINDOWS:
            if not kernel32.VirtualFree(address, 0, MEM_RELEASE):
                raise OSError(ctypes.get_last_error(), "VirtualFree failed")
        elif libc.munmap(address, size) != 0:
            e = ctypes.get_errno(); raise OSError(e, os.strerror(e))

    @staticmethod
    def flush_instruction_cache(address: int, size: int) -> None:
        if not IS_WINDOWS:
            return
        if not kernel32.FlushInstructionCache(kernel32.GetCurrentProcess(), address, size):
            raise OSError(ctypes.get_last_error(), "FlushInstructionCache failed")