"""Thread suspension for safe hot-patching (Scenario A + B).

enable()/disable() must not overwrite a function prologue while another thread
is executing it. The robust fix is to suspend every *other* thread, relocate any
thread whose instruction pointer — or, when the stolen region contains a call,
whose stack return address — points into the stolen region (redirecting it onto
the trampoline copy where the original instructions still live), then write the
patch and resume.

With all other threads suspended during the write, Scenario A (a thread seeing a
half-written patch at the entry point) is impossible regardless of how the bytes
are stored, and Scenario B (a thread parked inside the stolen region) is handled
by the relocation.

Windows implements suspension with the Toolhelp thread snapshot plus
SuspendThread + Get/SetThreadContext, for both x64 and x86 (WOW64/native 32-bit).
Linux has no in-process thread-suspend primitive — SIGSTOP is process-wide,
asynchronous, and can be cleared by an outside SIGCONT — so a signal-based
quiesce is the planned Linux backend. Until that lands, the Linux path writes the
patch without suspension; there, Scenario A is still closed by the atomic qword
store in core.py, but Scenario B is not covered, so hooks should be installed at
a quiescent moment.
"""
import ctypes
import sys

IS_WINDOWS = sys.platform == "win32"
_IS_64BIT = ctypes.sizeof(ctypes.c_void_p) == 8


def modify_threads_batch(operations) -> None:
    """Apply several prologue writes under a *single* process-wide suspension.

    *operations* is an iterable of ``(hook, apply_fn, relocate)`` tuples. Every
    other thread is suspended once; then, for each relocating op, any suspended
    thread parked in that hook's stolen region is redirected onto its trampoline;
    each thread whose context changed is pushed back once; every patch is written;
    finally all threads resume once.

    Doing the whole group inside one suspend/resume is both faster and safer than
    enabling hooks one at a time — threads never run free between two writes, so
    they cannot observe a half-installed set of hooks. On platforms without
    suspension support this just runs each *apply_fn* (no protection — see module
    docstring).
    """
    ops = [op for op in operations if op is not None]
    if not ops:
        return

    if not IS_WINDOWS:
        for _hook, apply_fn, _relocate in ops:
            apply_fn()
        return

    suspended = _suspend_others()
    try:
        # Accumulate IP relocations across every hook, then push each changed
        # context exactly once. (Stack return-address rewrites touch process
        # memory directly and take effect without SetThreadContext.)
        changed = {}  # index into `suspended` -> (handle, ctx)
        for hook, _apply_fn, relocate in ops:
            if relocate:
                for idx, (handle, ctx) in enumerate(suspended):
                    if _relocate_into(hook, handle, ctx):
                        changed[idx] = (handle, ctx)
        for handle, ctx in changed.values():
            if not kernel32.SetThreadContext(handle, ctypes.byref(ctx)):
                raise ctypes.WinError(ctypes.get_last_error())
        for _hook, apply_fn, _relocate in ops:
            apply_fn()
    finally:
        _resume(suspended)


def modify_threads(hook, apply_fn, *, relocate: bool) -> None:
    """Single-hook convenience wrapper over :func:`modify_threads_batch`."""
    modify_threads_batch([(hook, apply_fn, relocate)])


if IS_WINDOWS:
    from ctypes import wintypes

    # Suspending another thread must hold the GIL *across* the SuspendThread
    # call. A normal WinDLL releases the GIL during every foreign call; if it is
    # released here, the thread being suspended can acquire the GIL, run Python,
    # and then be frozen while still holding it — after which the suspender
    # deadlocks trying to reacquire the GIL. These WinAPI calls are short and
    # non-blocking, so we route them through a stdcall DLL that keeps the GIL
    # held (the _FUNCFLAG_PYTHONAPI flag), which makes suspend-the-world safe
    # even while other threads are hammering the target.
    _FUNCFLAG_STDCALL = getattr(ctypes, "_FUNCFLAG_STDCALL", 0x0)
    _FUNCFLAG_PYTHONAPI = getattr(ctypes, "_FUNCFLAG_PYTHONAPI", 0x4)

    class _GILSafeWinDLL(ctypes.WinDLL):
        _func_flags_ = _FUNCFLAG_STDCALL | _FUNCFLAG_PYTHONAPI

    kernel32 = _GILSafeWinDLL("kernel32", use_last_error=True)
    ntdll = _GILSafeWinDLL("ntdll", use_last_error=True)

    TH32CS_SNAPTHREAD = 0x00000004
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    THREAD_SUSPEND_RESUME = 0x0002
    THREAD_GET_CONTEXT = 0x0008
    THREAD_SET_CONTEXT = 0x0010
    THREAD_QUERY_INFORMATION = 0x0040
    _THREAD_ACCESS = (THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                      THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION)

    class THREADENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ThreadID", wintypes.DWORD),
            ("th32OwnerProcessID", wintypes.DWORD),
            ("tpBasePri", wintypes.LONG),
            ("tpDeltaPri", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
        ]

    class CLIENT_ID(ctypes.Structure):
        _fields_ = [("UniqueProcess", ctypes.c_void_p),
                    ("UniqueThread", ctypes.c_void_p)]

    class THREAD_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("ExitStatus", ctypes.c_long),
            ("TebBaseAddress", ctypes.c_void_p),
            ("ClientId", CLIENT_ID),
            ("AffinityMask", ctypes.c_void_p),
            ("Priority", ctypes.c_long),
            ("BasePriority", ctypes.c_long),
        ]

    if _IS_64BIT:
        CONTEXT_AMD64 = 0x00100000
        CONTEXT_FULL = CONTEXT_AMD64 | 0x1 | 0x2 | 0x8   # CONTROL|INTEGER|FLOATING_POINT
        _IP_FIELD, _SP_FIELD = "Rip", "Rsp"
        _TEB_STACKBASE_OFF = 0x08
        _SLOT = ctypes.c_uint64

        class M128A(ctypes.Structure):
            _pack_ = 16
            _fields_ = [("Low", ctypes.c_ulonglong), ("High", ctypes.c_longlong)]

        class CONTEXT(ctypes.Structure):
            # x64 CONTEXT: 16-byte aligned, 1232 bytes.
            _pack_ = 16
            _fields_ = [
                ("P1Home", ctypes.c_ulonglong), ("P2Home", ctypes.c_ulonglong),
                ("P3Home", ctypes.c_ulonglong), ("P4Home", ctypes.c_ulonglong),
                ("P5Home", ctypes.c_ulonglong), ("P6Home", ctypes.c_ulonglong),
                ("ContextFlags", wintypes.DWORD), ("MxCsr", wintypes.DWORD),
                ("SegCs", wintypes.WORD), ("SegDs", wintypes.WORD),
                ("SegEs", wintypes.WORD), ("SegFs", wintypes.WORD),
                ("SegGs", wintypes.WORD), ("SegSs", wintypes.WORD),
                ("EFlags", wintypes.DWORD),
                ("Dr0", ctypes.c_ulonglong), ("Dr1", ctypes.c_ulonglong),
                ("Dr2", ctypes.c_ulonglong), ("Dr3", ctypes.c_ulonglong),
                ("Dr6", ctypes.c_ulonglong), ("Dr7", ctypes.c_ulonglong),
                ("Rax", ctypes.c_ulonglong), ("Rcx", ctypes.c_ulonglong),
                ("Rdx", ctypes.c_ulonglong), ("Rbx", ctypes.c_ulonglong),
                ("Rsp", ctypes.c_ulonglong), ("Rbp", ctypes.c_ulonglong),
                ("Rsi", ctypes.c_ulonglong), ("Rdi", ctypes.c_ulonglong),
                ("R8", ctypes.c_ulonglong), ("R9", ctypes.c_ulonglong),
                ("R10", ctypes.c_ulonglong), ("R11", ctypes.c_ulonglong),
                ("R12", ctypes.c_ulonglong), ("R13", ctypes.c_ulonglong),
                ("R14", ctypes.c_ulonglong), ("R15", ctypes.c_ulonglong),
                ("Rip", ctypes.c_ulonglong),
                ("FltSave", ctypes.c_byte * 512),
                ("VectorRegister", M128A * 26),
                ("VectorControl", ctypes.c_ulonglong),
                ("DebugControl", ctypes.c_ulonglong),
                ("LastBranchToRip", ctypes.c_ulonglong),
                ("LastBranchFromRip", ctypes.c_ulonglong),
                ("LastExceptionToRip", ctypes.c_ulonglong),
                ("LastExceptionFromRip", ctypes.c_ulonglong),
            ]
    else:
        CONTEXT_i386 = 0x00010000
        CONTEXT_FULL = CONTEXT_i386 | 0x1 | 0x2 | 0x4   # CONTROL|INTEGER|SEGMENTS
        _IP_FIELD, _SP_FIELD = "Eip", "Esp"
        _TEB_STACKBASE_OFF = 0x04
        _SLOT = ctypes.c_uint32

        class FLOATING_SAVE_AREA(ctypes.Structure):
            _fields_ = [
                ("ControlWord", wintypes.DWORD), ("StatusWord", wintypes.DWORD),
                ("TagWord", wintypes.DWORD), ("ErrorOffset", wintypes.DWORD),
                ("ErrorSelector", wintypes.DWORD), ("DataOffset", wintypes.DWORD),
                ("DataSelector", wintypes.DWORD), ("RegisterArea", ctypes.c_byte * 80),
                ("Cr0NpxState", wintypes.DWORD),
            ]

        class CONTEXT(ctypes.Structure):
            # x86 CONTEXT: ~716 bytes.
            _fields_ = [
                ("ContextFlags", wintypes.DWORD),
                ("Dr0", wintypes.DWORD), ("Dr1", wintypes.DWORD),
                ("Dr2", wintypes.DWORD), ("Dr3", wintypes.DWORD),
                ("Dr6", wintypes.DWORD), ("Dr7", wintypes.DWORD),
                ("FloatSave", FLOATING_SAVE_AREA),
                ("SegGs", wintypes.DWORD), ("SegFs", wintypes.DWORD),
                ("SegEs", wintypes.DWORD), ("SegDs", wintypes.DWORD),
                ("Edi", wintypes.DWORD), ("Esi", wintypes.DWORD),
                ("Ebx", wintypes.DWORD), ("Edx", wintypes.DWORD),
                ("Ecx", wintypes.DWORD), ("Eax", wintypes.DWORD),
                ("Ebp", wintypes.DWORD), ("Eip", wintypes.DWORD),
                ("SegCs", wintypes.DWORD), ("EFlags", wintypes.DWORD),
                ("Esp", wintypes.DWORD), ("SegSs", wintypes.DWORD),
                ("ExtendedRegisters", ctypes.c_byte * 512),
            ]

    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
    kernel32.Thread32First.restype = wintypes.BOOL
    kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
    kernel32.Thread32Next.restype = wintypes.BOOL
    kernel32.OpenThread.restype = wintypes.HANDLE
    kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.SuspendThread.argtypes = [wintypes.HANDLE]
    kernel32.SuspendThread.restype = wintypes.DWORD
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.ResumeThread.restype = wintypes.DWORD
    kernel32.GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.POINTER(CONTEXT)]
    kernel32.GetThreadContext.restype = wintypes.BOOL
    kernel32.SetThreadContext.argtypes = [wintypes.HANDLE, ctypes.POINTER(CONTEXT)]
    kernel32.SetThreadContext.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.GetCurrentThreadId.restype = wintypes.DWORD
    kernel32.GetCurrentProcessId.restype = wintypes.DWORD
    ntdll.NtQueryInformationThread.argtypes = [
        wintypes.HANDLE, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong)]
    ntdll.NtQueryInformationThread.restype = ctypes.c_long

    def _suspend_others():
        """Suspend every thread in this process except the caller. Returns a list
        of (handle, CONTEXT) for each successfully suspended thread."""
        me_pid = kernel32.GetCurrentProcessId()
        me_tid = kernel32.GetCurrentThreadId()
        snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        if snap == INVALID_HANDLE_VALUE:
            raise ctypes.WinError(ctypes.get_last_error())
        suspended = []
        try:
            entry = THREADENTRY32()
            entry.dwSize = ctypes.sizeof(THREADENTRY32)
            ok = kernel32.Thread32First(snap, ctypes.byref(entry))
            while ok:
                if (entry.th32OwnerProcessID == me_pid
                        and entry.th32ThreadID != me_tid):
                    handle = kernel32.OpenThread(_THREAD_ACCESS, False, entry.th32ThreadID)
                    if handle:
                        if kernel32.SuspendThread(handle) != 0xFFFFFFFF:
                            ctx = CONTEXT()
                            ctx.ContextFlags = CONTEXT_FULL
                            # GetThreadContext forces the suspend to complete:
                            # the thread is truly off-core once it returns.
                            if kernel32.GetThreadContext(handle, ctypes.byref(ctx)):
                                suspended.append((handle, ctx))
                                entry.dwSize = ctypes.sizeof(THREADENTRY32)
                                ok = kernel32.Thread32Next(snap, ctypes.byref(entry))
                                continue
                            kernel32.ResumeThread(handle)
                        kernel32.CloseHandle(handle)
                entry.dwSize = ctypes.sizeof(THREADENTRY32)
                ok = kernel32.Thread32Next(snap, ctypes.byref(entry))
        finally:
            kernel32.CloseHandle(snap)
        return suspended

    def _stack_base(handle):
        tbi = THREAD_BASIC_INFORMATION()
        status = ntdll.NtQueryInformationThread(
            handle, 0, ctypes.byref(tbi), ctypes.sizeof(tbi), None)
        if status != 0 or not tbi.TebBaseAddress:
            return None
        # NT_TIB is at the start of the TEB; StackBase is at _TEB_STACKBASE_OFF.
        return _SLOT.from_address(tbi.TebBaseAddress + _TEB_STACKBASE_OFF).value

    def _relocate_into(hook, handle, ctx):
        """Redirect a suspended thread parked in *hook*'s stolen region onto the
        trampoline copy. Mutates *ctx* in place and returns True when the
        instruction pointer changed (so the batch driver pushes it once). Stack
        return-address rewrites are applied directly to process memory here and
        need no SetThreadContext."""
        changed = False
        ip = getattr(ctx, _IP_FIELD)
        new_ip = hook.relocate_stolen(ip)
        if new_ip is not None:
            setattr(ctx, _IP_FIELD, new_ip)
            changed = True
        if hook.stolen_has_call:
            base = _stack_base(handle)
            sp = getattr(ctx, _SP_FIELD)
            if base is not None and base > sp:
                step = ctypes.sizeof(_SLOT)
                addr = sp
                while addr + step <= base:
                    slot = _SLOT.from_address(addr)
                    new = hook.relocate_stolen(slot.value)
                    if new is not None:
                        slot.value = new
                    addr += step
        return changed

    def _resume(suspended):
        for handle, _ctx in suspended:
            kernel32.ResumeThread(handle)
            kernel32.CloseHandle(handle)
