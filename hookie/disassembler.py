import ctypes

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

from .memory import MemoryManager


LOOP_MNEMONICS = {"loop", "loope", "loopz", "loopne", "loopnz", "jcxz", "jecxz", "jrcxz"}


class Disassembler:
    READ_SIZE = 64

    def __init__(self, bits: int):
        if bits not in (32, 64):
            raise ValueError("bits must be 32 or 64")
        self.bits = bits
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64 if bits == 64 else CS_MODE_32)
        self.cs.detail = True

    def disassemble(self, address: int, size: int | None = None):
        if address <= 0:
            raise ValueError("address must be greater than zero")
        if size is None:
            size = self.READ_SIZE
        if size <= 0:
            raise ValueError("size must be greater than zero")
        # Clamp to what is actually mapped+readable so a fixed-size prologue
        # read cannot fault past the end of a mapping into an unmapped page.
        safe = MemoryManager.readable_extent(address, size)
        if safe <= 0:
            raise ValueError(f"target address 0x{address:X} is not readable")
        raw = ctypes.string_at(address, safe)
        return list(self.cs.disasm(raw, address))

    @staticmethod
    def is_terminal(ins) -> bool:
        return ins.mnemonic.startswith("ret") or ins.mnemonic in ("int3", "ud2")

    @staticmethod
    def _stops_after(ins) -> bool:
        """Koşulsuz jmp'in fall-through'u yoktur; ötesindeki baytlar veri,
        padding, jump-table ya da komşu fonksiyon olabilir. Buraya kadar olan
        komutu dahil et, ama asla ötesini disassemble etme."""
        return ins.mnemonic == "jmp"

    def available_prologue_size(self, address: int, limit: int = 14) -> int:
        if limit <= 0:
            raise ValueError("limit must be greater than zero")
        total = 0
        for ins in self.disassemble(address):
            if self.is_terminal(ins):
                break
            total += ins.size
            if total >= limit:
                break
            if self._stops_after(ins):
                break
        return total

    def collect_instructions(self, address: int, minimum_size: int):
        if minimum_size <= 0:
            raise ValueError("minimum_size must be greater than zero")
        out = []
        total = 0
        for ins in self.disassemble(address):
            if self.is_terminal(ins):
                break
            out.append(ins)
            total += ins.size
            if total >= minimum_size:
                break
            if self._stops_after(ins):
                break
        if total < minimum_size:
            raise ValueError(f"Not enough instructions for hook: need {minimum_size}, got {total}")
        return out, total

    def is_rip_relative(self, ins) -> bool:
        if self.bits != 64:
            return False
        return any(op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP for op in ins.operands)

    @staticmethod
    def branch_target(ins):
        is_branch = ins.group(CS_GRP_CALL) or ins.group(CS_GRP_JUMP) or ins.mnemonic in LOOP_MNEMONICS
        if not is_branch or ins.imm_size == 0 or not ins.operands:
            return None
        return ins.operands[0].imm