import ctypes
import struct

from .memory import MemoryManager
from .arch.x64 import x64Arch
from .arch.x86 import x86Arch
from .disassembler import Disassembler, LOOP_MNEMONICS


_JCC_CC = {
    "jo": 0x0, "jno": 0x1, "jb": 0x2, "jae": 0x3,
    "je": 0x4, "jne": 0x5, "jbe": 0x6, "ja": 0x7,
    "js": 0x8, "jns": 0x9, "jp": 0xA, "jnp": 0xB,
    "jl": 0xC, "jge": 0xD, "jle": 0xE, "jg": 0xF,
}
class TrampolineBuilder:
    READ_SIZE = 64

    def __init__(self, target_addr: int, disassembler: Disassembler):
        if target_addr <= 0:
            raise ValueError("target_addr must be greater than zero")
        self.target_addr = target_addr
        self.disassembler = disassembler
        self.bits = disassembler.bits
        self.arch = x64Arch if self.bits == 64 else x86Arch

    def _collect_stolen_instructions(self, min_stolen_size: int):
        return self.disassembler.collect_instructions(self.target_addr, min_stolen_size)

    @staticmethod
    def _fits_signed(v: int, size: int) -> bool:
        bits = size * 8
        return -(1 << (bits - 1)) <= v <= (1 << (bits - 1)) - 1

    @staticmethod
    def _pack_signed(v: int, size: int) -> bytes:
        return {1: lambda: struct.pack('<b', v), 2: lambda: struct.pack('<h', v),
                4: lambda: struct.pack('<i', v), 8: lambda: struct.pack('<q', v)}[size]()

    @staticmethod
    def _kind(ins) -> str:
        m = ins.mnemonic
        if m in LOOP_MNEMONICS:
            return "loop"
        if m == "call":
            return "call"
        if m == "jmp":
            return "jmp"
        if m in _JCC_CC:
            return "jcc"
        return "normal"

    def _planned_size(self, ins, stolen_start: int, stolen_end: int) -> int:
        target = self.disassembler.branch_target(ins)
        kind = self._kind(ins)
        if target is None:
            return ins.size
        intra = stolen_start <= target < stolen_end
        if kind == "loop":
            return ins.size + 2 + (14 if self.bits == 64 else 5)
        if self.bits == 32:
            return {"call": 5, "jmp": 5, "jcc": 6}.get(kind, ins.size)
        if intra:
            return {"call": 5, "jmp": 5, "jcc": 6}.get(kind, ins.size)
        return {"call": 16, "jmp": 14, "jcc": 16}.get(kind, ins.size)

    def _plan_layout(self, instructions, stolen_start: int, stolen_end: int):
        plan, off = [], 0
        for ins in instructions:
            size = self._planned_size(ins, stolen_start, stolen_end)
            plan.append({"ins": ins, "off": off, "size": size})
            off += size
        return plan, off

    def _allocate(self, plan, total_size: int) -> int:
        if self.bits == 32:
            return MemoryManager.allocate_rw(total_size)

        constraints = []
        for p in plan:
            ins = p["ins"]
            if not self.disassembler.is_rip_relative(ins):
                continue
            data_target = ins.address + ins.size + ins.disp
            c = p["off"]
            s = ins.size
            # -2^31 <= D-(base+c+s) <= 2^31-1
            base_low = data_target - c - s - ((1 << 31) - 1)
            base_high = data_target - c - s + (1 << 31)
            constraints.append((base_low, base_high))

        if not constraints:
            return MemoryManager.allocate_rw(total_size)

        base_low = max(x[0] for x in constraints)
        base_high = min(x[1] for x in constraints)
        if base_low > base_high:
            raise RuntimeError("RIP-relative constraints have no common trampoline base range")

        # allocate_near constrains the whole block to [low, high]. Convert the
        # exact allowed BASE interval [base_low, base_high] accordingly.
        alloc_high = base_high + total_size - 1
        addr = MemoryManager.allocate_near(total_size, base_low, alloc_high)
        if addr is None:
            raise RuntimeError(
                f"No free executable block in exact RIP-relative base range "
                f"[0x{base_low:X}, 0x{base_high:X}]"
            )
        if not base_low <= addr <= base_high:
            MemoryManager.free_rwx(addr, total_size)
            raise RuntimeError("allocator returned a base outside the requested RIP-relative range")
        return addr

    def _relocate_rip(self, ins, new_addr: int, data: bytearray):
        target = ins.address + ins.size + ins.disp
        d = target - (new_addr + ins.size)
        if not self._fits_signed(d, ins.disp_size):
            raise OverflowError(f"RIP-relative displacement out of range at 0x{ins.address:X}")
        data[ins.disp_offset:ins.disp_offset + ins.disp_size] = self._pack_signed(d, ins.disp_size)

    @staticmethod
    def _near_jcc(cc: int, src: int, dst: int, arch) -> bytes:
        return bytes((0x0F, 0x80 | cc)) + arch.make_rel32(src, 6, dst)

    def _emit_loop(self, ins, src: int, dst: int) -> bytes:
        # Preserve prefixes/opcode exactly; only replace original rel8 with +2.
        head = bytearray(ins.bytes)
        if ins.imm_size != 1:
            raise RuntimeError(f"Unexpected LOOP/J*CXZ encoding at 0x{ins.address:X}")
        head[ins.imm_offset] = 2  # taken -> skip EB and execute long jump
        if self.bits == 64:
            return bytes(head) + b"\xEB\x0E" + x64Arch.make_absolute_jmp(dst)
        long_src = src + len(head) + 2
        return bytes(head) + b"\xEB\x05" + b"\xE9" + x86Arch.make_rel32(long_src, 5, dst)

    def _emit(self, p, trampoline_addr: int, addr_map: dict[int, int], stolen_start: int, stolen_end: int) -> bytes:
        ins, off = p["ins"], p["off"]
        src = trampoline_addr + off
        target = self.disassembler.branch_target(ins)
        kind = self._kind(ins)

        if target is None:
            data = bytearray(ins.bytes)
            if self.disassembler.is_rip_relative(ins):
                self._relocate_rip(ins, src, data)
            return bytes(data)

        intra = stolen_start <= target < stolen_end
        if intra:
            if target not in addr_map:
                raise RuntimeError(
                    f"Branch into middle of stolen instruction is unsupported: 0x{ins.address:X} -> 0x{target:X}"
                )
            dst = addr_map[target]
        else:
            dst = target

        if kind == "loop":
            return self._emit_loop(ins, src, dst)

        if self.bits == 32:
            if kind == "call": return b"\xE8" + x86Arch.make_rel32(src, 5, dst)
            if kind == "jmp": return b"\xE9" + x86Arch.make_rel32(src, 5, dst)
            if kind == "jcc": return self._near_jcc(_JCC_CC[ins.mnemonic], src, dst, x86Arch)

        if intra:
            if kind == "call": return b"\xE8" + x64Arch.make_rel32(src, 5, dst)
            if kind == "jmp": return b"\xE9" + x64Arch.make_rel32(src, 5, dst)
            if kind == "jcc": return self._near_jcc(_JCC_CC[ins.mnemonic], src, dst, x64Arch)
        else:
            if kind == "call": return x64Arch.make_absolute_call(dst)
            if kind == "jmp": return x64Arch.make_absolute_jmp(dst)
            if kind == "jcc":
                inv = _JCC_CC[ins.mnemonic] ^ 1
                return bytes((0x70 | inv, 14)) + x64Arch.make_absolute_jmp(dst)

        raise RuntimeError(f"Unsupported relative control-flow instruction: {ins.mnemonic} {ins.op_str}")

    def build(self, min_stolen_size: int | None = None):
        if min_stolen_size is None:
            min_stolen_size = 14 if self.bits == 64 else 5
        if min_stolen_size <= 0:
            raise ValueError("min_stolen_size must be greater than zero")
        instructions, stolen_size = self._collect_stolen_instructions(min_stolen_size)
        original_bytes = ctypes.string_at(self.target_addr, stolen_size)
        stolen_start, stolen_end = self.target_addr, self.target_addr + stolen_size
        plan, body_size = self._plan_layout(instructions, stolen_start, stolen_end)
        resume_size = 14 if self.bits == 64 else 5
        trampoline_size = body_size + resume_size
        trampoline_addr = self._allocate(plan, trampoline_size)

        try:
            addr_map = {p["ins"].address: trampoline_addr + p["off"] for p in plan}
            code = bytearray()
            for p in plan:
                emitted = self._emit(p, trampoline_addr, addr_map, stolen_start, stolen_end)
                if len(emitted) != p["size"]:
                    raise RuntimeError(
                        f"layout mismatch at 0x{p['ins'].address:X}: planned {p['size']}, emitted {len(emitted)}"
                    )
                code.extend(emitted)

            resume = self.target_addr + stolen_size
            resume_src = trampoline_addr + len(code)
            if self.bits == 64:
                code.extend(x64Arch.make_absolute_jmp(resume))
            else:
                code.extend(b"\xE9" + x86Arch.make_rel32(resume_src, 5, resume))

            if len(code) != trampoline_size:
                raise RuntimeError(
                    f"trampoline size mismatch: planned {trampoline_size}, emitted {len(code)}"
                )
            ctypes.memmove(trampoline_addr, bytes(code), len(code))
            MemoryManager.flush_instruction_cache(trampoline_addr, len(code))
            MemoryManager.protect_rx(trampoline_addr, trampoline_size)  # W^X: RW -> R-X
            return {
                "bits": self.bits,
                "stolen_size": stolen_size,
                "original_bytes": original_bytes,
                "trampoline_addr": trampoline_addr,
                "trampoline_size": trampoline_size,
                "code_size": len(code),
            }
        except Exception:
            MemoryManager.free_rwx(trampoline_addr, trampoline_size)
            raise
