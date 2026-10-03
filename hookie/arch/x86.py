import struct


class x86Arch:
    MODE_BITS = 32
    PATCH_SIZE = 5
    JMP_SIZE = PATCH_SIZE
    POINTER_SIZE = 4

    @staticmethod
    def _u32(value: int) -> int:
        return value & 0xFFFFFFFF

    @staticmethod
    def make_rel32(source_addr: int, instruction_size: int, target_addr: int) -> bytes:
        """x86'da rel32 tüm 32-bit address space'i modulo 2^32 kapsar."""
        d = x86Arch._u32(target_addr - (source_addr + instruction_size))
        return struct.pack("<I", d)

    @staticmethod
    def fits_rel32(source_addr: int, instruction_size: int, target_addr: int) -> bool:
        return True

    @staticmethod
    def make_absolute_jmp(target_addr: int, source_addr: int | None = None) -> bytes:
        if source_addr is None:
            raise ValueError("x86 JMP requires source_addr so E9 rel32 can be encoded")
        return b"\xE9" + x86Arch.make_rel32(source_addr, 5, target_addr)

    @staticmethod
    def make_absolute_call(target_addr: int, source_addr: int | None = None) -> bytes:
        if source_addr is None:
            raise ValueError("x86 CALL requires source_addr so E8 rel32 can be encoded")
        return b"\xE8" + x86Arch.make_rel32(source_addr, 5, target_addr)
