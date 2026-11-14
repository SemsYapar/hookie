import ctypes
import logging
import weakref
from typing import Any, Callable, Sequence

from .memory import MemoryManager
from .threads import modify_threads_batch, IS_WINDOWS, _IS_64BIT
from .trampoline import TrampolineBuilder
from .disassembler import Disassembler
from .arch.x64 import x64Arch
from .arch.x86 import x86Arch

# Library logger. Silent by default (NullHandler); a user calls
# hookie.log_to_file(path) or configures the "hookie" logger themselves to
# capture how each hook was installed — useful when a hook crashes a process and
# you want to look back at which patch strategy and thread policy were chosen.
logger = logging.getLogger("hookie")
logger.addHandler(logging.NullHandler())


def _thread_policy() -> str:
    if IS_WINDOWS:
        return "suspend/windows-x64" if _IS_64BIT else "suspend/windows-x86"
    return "none/linux (atomic entry-write only)"


class Hook:
    def __init__(self, target_addr: int, detour_addr: int, trampoline_info: dict,
                 original_ctype_func: Any, c_detour_ref: Any, patch: bytes,
                 relay_addr: int = 0, relay_size: int = 0, owner=None):
        self.target_addr = target_addr
        self.detour_addr = detour_addr
        self.bits = trampoline_info["bits"]
        self.arch = x64Arch if self.bits == 64 else x86Arch
        self.stolen_size = trampoline_info["stolen_size"]
        self.original_bytes = trampoline_info["original_bytes"]
        self.trampoline_addr = trampoline_info["trampoline_addr"]
        self.trampoline_size = trampoline_info["trampoline_size"]
        self.trampoline_code_size = trampoline_info["code_size"]
        self._addr_map = trampoline_info.get("addr_map", {})
        # True when the stolen region contains a call: then a thread can have a
        # *return address* (on its stack) pointing into the stolen region, not
        # just its RIP. Retargeting RIP alone is then insufficient — the stack
        # must be scanned too. (This is the case MinHook does not handle.)
        self.stolen_has_call = trampoline_info.get("stolen_has_call", False)
        self.relay_addr = relay_addr
        self.relay_size = relay_size
        self.original = original_ctype_func
        self._c_detour_ref = c_detour_ref
        self.is_enabled = False
        self.is_destroyed = False
        self._prologue_uncertain = False
        self._owner_ref = weakref.ref(owner) if owner is not None else None

        if len(patch) > self.stolen_size:
            raise RuntimeError(f"Hook patch is larger than stolen region: patch={len(patch)}, stolen={self.stolen_size}")
        self.jmp_patch = patch + b"\x90" * (self.stolen_size - len(patch))
        # Length of the real jmp (without the NOP tail). A 5-byte rel32 fits one
        # aligned qword and is written atomically; the 14-byte absolute jmp
        # cannot (its operand straddles the window) and stays on the memmove
        # path. With the rel32-first patch strategy, the atomic path is the norm.
        self._core_len = len(patch)

    def _check_alive(self):
        if self.is_destroyed:
            raise RuntimeError("Hook has already been destroyed")

    def relocate_stolen(self, addr: int) -> int | None:
        """Map an address inside the stolen prologue to its trampoline copy.

        *addr* is a value captured from a suspended thread — either its RIP or a
        return address found on its stack. If it lands inside the stolen region
        this returns the equivalent address in the trampoline (where the
        original instructions still live), so the thread can be redirected there
        before the prologue is overwritten. Returns None when *addr* is outside
        the stolen region (nothing to do) or does not fall on a stolen
        instruction boundary (unexpected; the caller should refuse rather than
        guess).
        """
        if not (self.target_addr <= addr < self.target_addr + self.stolen_size):
            return None
        return self._addr_map.get(addr)

    def _raw_write(self, data: bytes):
        """Write *data* over the prologue, assuming the page is already writable.

        Two layers of safety, independent of each other:

        - On Windows, enable()/disable() already run under modify_threads_batch,
          which suspends every other thread, so the write never races a live
          execution.
        - On every platform, when the critical jmp fits one 8-aligned window the
          first qword (carrying that jmp) is stored atomically. This closes
          Scenario A on Linux too, where thread suspension is not yet available —
          a thread entering at the first byte sees either the whole old prologue
          or the whole new jmp. Trailing padding past the jmp (unreachable once
          the jmp is taken) goes via memmove. The 14-byte absolute jmp does not
          fit the window, so it falls back to a plain memmove.
        """
        n = len(data)
        base = self.target_addr & ~7
        off = self.target_addr - base
        if self._core_len <= 8 and off + self._core_len <= 8:
            win = min(8 - off, n)
            current = ctypes.string_at(base, 8)
            merged = bytearray(current)
            merged[off:off + win] = data[:win]
            MemoryManager.write_qword_atomic(base, int.from_bytes(merged, "little"))
            if win < n:
                ctypes.memmove(self.target_addr + win, data[win:], n - win)
        else:
            ctypes.memmove(self.target_addr, data, n)
        MemoryManager.flush_instruction_cache(self.target_addr, n)

    def _apply_bytes(self, data: bytes) -> bytes:
        """Transactionally write *data* over the prologue and report the bytes
        actually left there, so the caller can keep ``is_enabled`` in sync with
        reality. Guarantees:

        - ``make_rwx`` failing before any store leaves the prologue untouched
          and simply propagates (caller's flag already matches reality).
        - a store that lands but then fails (flush/partial) is rolled back to
          ``original_bytes``; the return value says which state won.
        - protection-restore failure is swallowed: the page is left R-W-X,
          which is degraded but never corrupting.
        - only a failure to even roll back raises, with
          ``_prologue_uncertain`` set so teardown won't free reachable code.
        """
        length = len(data)
        old = MemoryManager.make_rwx(self.target_addr, length)
        try:
            try:
                self._raw_write(data)
                return data
            except Exception:
                try:
                    self._raw_write(self.original_bytes)
                    return self.original_bytes
                except Exception as rollback_err:
                    self._prologue_uncertain = True
                    raise RuntimeError(
                        "hook prologue left indeterminate: patch and rollback "
                        "both failed") from rollback_err
        finally:
            try:
                MemoryManager.restore_protection(self.target_addr, length, old)
            except OSError:
                pass  # page left R-W-X: degraded, not corrupting

    def _enable_op(self):
        """Build the ``(hook, apply_fn, relocate)`` tuple for enabling this hook,
        or None if it is already enabled. The returned apply_fn runs with every
        other thread suspended and any thread parked in the stolen region already
        relocated onto the trampoline, so the prologue can be overwritten without
        racing a live execution. Logging is deliberately left to the caller, after
        resume — doing I/O while threads are suspended risks a lock-ordering
        deadlock against a suspended thread."""
        self._check_alive()
        if self.is_enabled:
            return None

        def apply():
            if self._apply_bytes(self.jmp_patch) != self.jmp_patch:
                raise RuntimeError("enable failed; prologue rolled back to original")
            self.is_enabled = True

        return (self, apply, True)

    def _disable_op(self):
        """Symmetric with :meth:`_enable_op`. No relocation needed — restoring the
        original bytes is exactly what any thread at the entry point should run."""
        self._check_alive()
        if not self.is_enabled:
            return None

        def apply():
            self._apply_bytes(self.original_bytes)  # returns original_bytes, or raises
            self.is_enabled = False

        return (self, apply, False)

    def enable(self):
        op = self._enable_op()
        if op is None:
            return
        modify_threads_batch([op])
        logger.info("hook enabled: target=0x%X", self.target_addr)

    def disable(self):
        op = self._disable_op()
        if op is None:
            return
        modify_threads_batch([op])
        logger.info("hook disabled: target=0x%X", self.target_addr)

    def _detach_from_owner(self):
        if self._owner_ref is None:
            return
        owner = self._owner_ref()
        if owner is not None:
            owner._forget(self)
        self._owner_ref = None

    def destroy(self):
        """Safely remove the hook and release its owned executable memory.

        Destruction is deliberately fail-closed.  If the target prologue cannot
        be proven restored to the original bytes, none of the trampoline, relay,
        original thunk, or ctypes callback references are released.  Those
        objects may still be reachable from native code.
        """
        if self.is_destroyed:
            return
        if self._prologue_uncertain:
            raise RuntimeError(
                "cannot destroy hook safely: target prologue state is uncertain; "
                "hook resources were kept alive")

        # Propagate disable failures.  In particular, make_rwx() can fail before
        # any store while the detour remains active; freeing resources after such
        # a failure would create an immediate use-after-free path.
        if self.is_enabled:
            self.disable()

        if self._prologue_uncertain:
            raise RuntimeError(
                "cannot destroy hook safely: target prologue state became uncertain; "
                "hook resources were kept alive")

        # From this point onward the target prologue is confirmed original, so
        # native execution can no longer reach the detour/trampoline/relay.
        # Deallocation failures are therefore cleanup errors, not a reason to
        # leave Python callables pointing at memory that may already be freed.
        cleanup_errors = []
        if self.trampoline_addr:
            try:
                MemoryManager.free_rwx(self.trampoline_addr, self.trampoline_size)
            except Exception as exc:
                cleanup_errors.append(exc)
            else:
                self.trampoline_addr = 0
        if self.relay_addr:
            try:
                MemoryManager.free_rwx(self.relay_addr, self.relay_size)
            except Exception as exc:
                cleanup_errors.append(exc)
            else:
                self.relay_addr = 0

        self.original = None
        self._c_detour_ref = None
        self.is_destroyed = True
        self._detach_from_owner()

        if cleanup_errors:
            raise RuntimeError(
                f"hook was detached safely, but {len(cleanup_errors)} executable "
                "allocation(s) could not be freed") from cleanup_errors[0]


class HookEngine:
    RELAY_SIZE = 14

    def __init__(self, bits: int | None = None):
        if bits is None:
            bits = ctypes.sizeof(ctypes.c_void_p) * 8
        if bits not in (32, 64):
            raise ValueError("bits must be 32 or 64")
        self.bits = bits
        self.arch = x64Arch if bits == 64 else x86Arch
        self.disassembler = Disassembler(bits)
        self.hooks: list[Hook] = []

    @staticmethod
    def _allocate_x64_relay(target_addr: int, detour_addr: int) -> tuple[int, int]:
        # E9 displacement is relative to target+5.
        base_low = target_addr + 5 - (1 << 31)
        base_high = target_addr + 5 + ((1 << 31) - 1)
        alloc_high = base_high + HookEngine.RELAY_SIZE - 1
        relay = MemoryManager.allocate_near(HookEngine.RELAY_SIZE, base_low, alloc_high)
        if not relay or not base_low <= relay <= base_high:
            if relay:
                MemoryManager.free_rwx(relay, HookEngine.RELAY_SIZE)
            raise RuntimeError("Could not allocate x64 relay inside target rel32 range")
        code = x64Arch.make_absolute_jmp(detour_addr)
        try:
            ctypes.memmove(relay, code, len(code))
            MemoryManager.flush_instruction_cache(relay, len(code))
            MemoryManager.protect_rx(relay, HookEngine.RELAY_SIZE)  # W^X: RW -> R-X
        except Exception:
            MemoryManager.free_rwx(relay, HookEngine.RELAY_SIZE)
            raise
        return relay, HookEngine.RELAY_SIZE

    def _select_patch(self, target_addr: int, detour_addr: int):
        if self.bits == 32:
            available = self.disassembler.available_prologue_size(target_addr, 5)
            if available < 5:
                raise ValueError(f"Not enough instructions for hook: need 5, got {available}")
            return 5, b"\xE9" + x86Arch.make_rel32(target_addr, 5, detour_addr), 0, 0

        # rel32-first: a 5-byte rel32 jmp fits one aligned qword and can be
        # written atomically (closes Scenario A even without thread suspension,
        # e.g. on Linux). It also steals fewer bytes, so shorter prologues are
        # hookable. The 14-byte absolute jmp is a last resort — used only when
        # the detour is out of rel32 range AND no near memory is free for a
        # relay AND the prologue is long enough for the absolute form.
        available = self.disassembler.available_prologue_size(target_addr, 14)
        if available < 5:
            raise ValueError(f"Not enough instructions for x64 hook: need at least 5, got {available}")

        # 1) Direct rel32 when the detour is within range.
        if x64Arch.fits_rel32(target_addr, 5, detour_addr):
            return 5, b"\xE9" + x64Arch.make_rel32(target_addr, 5, detour_addr), 0, 0

        # 2) rel32 -> nearby relay -> absolute jmp to the far detour.
        try:
            relay, relay_size = self._allocate_x64_relay(target_addr, detour_addr)
        except RuntimeError:
            relay = None
        if relay is not None:
            try:
                patch = b"\xE9" + x64Arch.make_rel32(target_addr, 5, relay)
            except Exception:
                MemoryManager.free_rwx(relay, relay_size)
                raise
            return 5, patch, relay, relay_size

        # 3) Last resort: a direct 14-byte absolute jmp (not atomically writable).
        if available >= 14:
            return 14, x64Arch.make_absolute_jmp(detour_addr), 0, 0
        raise ValueError(
            "cannot hook: detour out of rel32 range, no near memory for a relay, "
            f"and prologue too short for a 14-byte absolute jmp (have {available})")

    def _ensure_no_overlap(self, target_addr: int, stolen_size: int) -> None:
        new_lo, new_hi = target_addr, target_addr + stolen_size
        for h in self.hooks:
            if h.is_destroyed:
                continue
            lo, hi = h.target_addr, h.target_addr + h.stolen_size
            if new_lo < hi and lo < new_hi:
                raise ValueError(
                    f"hook region [0x{new_lo:X},0x{new_hi:X}) overlaps an existing "
                    f"hook [0x{lo:X},0x{hi:X})")

    def create_hook(self, target_addr: int, detour_func: Callable, arg_types: Sequence[Any],
                    restype: Any, *, prototype_factory=ctypes.CFUNCTYPE) -> Hook:
        if target_addr <= 0:
            raise ValueError("target_addr must be greater than zero")

        c_func_type = prototype_factory(restype, *arg_types)
        c_detour = c_func_type(detour_func)
        detour_addr = ctypes.cast(c_detour, ctypes.c_void_p).value
        if not detour_addr:
            raise RuntimeError("Could not obtain detour function address")

        builder = TrampolineBuilder(target_addr, self.disassembler)
        relay_addr = relay_size = 0
        trampoline_info = None
        try:
            patch_size, patch, relay_addr, relay_size = self._select_patch(target_addr, detour_addr)
            trampoline_info = builder.build(min_stolen_size=patch_size)
            self._ensure_no_overlap(target_addr, trampoline_info["stolen_size"])
            original_ctype_func = c_func_type(trampoline_info["trampoline_addr"])
            hook = Hook(target_addr, detour_addr, trampoline_info, original_ctype_func,
                        c_detour, patch, relay_addr, relay_size, owner=self)
        except Exception as exc:
            if trampoline_info:
                MemoryManager.free_rwx(trampoline_info["trampoline_addr"], trampoline_info["trampoline_size"])
            if relay_addr:
                MemoryManager.free_rwx(relay_addr, relay_size)
            logger.warning("hook FAILED: target=0x%X bits=%d: %s", target_addr, self.bits, exc)
            raise

        if patch_size >= 14:
            strategy = "abs14"          # last resort, NOT atomically writable
        elif relay_addr:
            strategy = "rel32+relay"    # far detour reached via a nearby relay
        else:
            strategy = "rel32"          # direct 5-byte jump
        atomic = hook._core_len <= 8
        logger.info(
            "hook installed: target=0x%X detour=0x%X strategy=%s stolen=%dB "
            "atomic_write=%s stolen_has_call=%s threads=%s",
            target_addr, detour_addr, strategy, hook.stolen_size,
            "yes" if atomic else "no", "yes" if hook.stolen_has_call else "no",
            _thread_policy())

        self.hooks.append(hook)
        return hook

    def enable_all(self):
        """Enable every hook under a single process-wide suspension, rather than
        suspending and resuming once per hook."""
        ops = [op for op in (hook._enable_op() for hook in self.hooks)
               if op is not None]
        if not ops:
            return
        modify_threads_batch(ops)
        for hook, _apply, _relocate in ops:
            logger.info("hook enabled: target=0x%X", hook.target_addr)

    def disable_all(self):
        """Disable every hook under a single process-wide suspension."""
        ops = [op for op in (hook._disable_op() for hook in self.hooks)
               if op is not None]
        if not ops:
            return
        modify_threads_batch(ops)
        for hook, _apply, _relocate in ops:
            logger.info("hook disabled: target=0x%X", hook.target_addr)

    def _forget(self, hook: Hook) -> None:
        try:
            self.hooks.remove(hook)
        except ValueError:
            pass

    def destroy_hook(self, hook: Hook):
        if hook not in self.hooks:
            raise ValueError("Hook does not belong to this HookEngine")
        hook.destroy()  # successful destroy detaches itself from this engine

    def destroy_all(self):
        failures = []
        for hook in self.hooks[:]:
            try:
                hook.destroy()
            except Exception as exc:
                failures.append((hook, exc))
        if failures:
            first = failures[0][1]
            unsafe = sum(1 for hook, _ in failures if not hook.is_destroyed)
            if unsafe:
                raise RuntimeError(
                    f"{unsafe} hook(s) could not be detached safely; their native-"
                    "reachable resources were kept alive") from first
            raise RuntimeError(
                f"{len(failures)} hook(s) detached safely but reported cleanup errors") from first

    def unhook_all(self):
        self.disable_all()
