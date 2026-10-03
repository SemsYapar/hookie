import struct


class x64Arch:
    MODE_BITS = 64
    REL32_JMP_SIZE = 5
    ABS_JMP_SIZE = 14
    PATCH_SIZE = ABS_JMP_SIZE  # compatibility only; strategy chooses 5 or 14
    JMP_SIZE = ABS_JMP_SIZE
    POINTER_SIZE = 8

    @staticmethod
    def make_absolute_jmp(target_addr: int) -> bytes:
        if not 0 <= target_addr <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("target_addr is not a valid 64-bit address")
        return b"\xFF\x25\x00\x00\x00\x00" + struct.pack("<Q", target_addr)

    @staticmethod
    def make_absolute_call(target_addr: int) -> bytes:
        """Register bozmayan absolute CALL.

        call qword ptr [rip+2]
        jmp short +8
        dq target
        """
        if not 0 <= target_addr <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("target_addr is not a valid 64-bit address")
        return b"\xFF\x15\x02\x00\x00\x00\xEB\x08" + struct.pack("<Q", target_addr)

    @staticmethod
    def fits_rel32(source_addr: int, instruction_size: int, target_addr: int) -> bool:
        d = target_addr - (source_addr + instruction_size)
        return -(1 << 31) <= d <= (1 << 31) - 1

    @staticmethod
    def make_rel32(source_addr: int, instruction_size: int, target_addr: int) -> bytes:
        d = target_addr - (source_addr + instruction_size)
        if not -(1 << 31) <= d <= (1 << 31) - 1:
            raise OverflowError(
                f"rel32 target out of range: source=0x{source_addr:X}, target=0x{target_addr:X}"
            )
        return struct.pack("<i", d)
