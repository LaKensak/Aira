"""Désassemblage de l'entry point (capstone optionnel)."""
from __future__ import annotations

from typing import Optional


def disasm_entrypoint(binary_path: str, n_bytes: int = 80) -> Optional[dict]:
    """
    Désassemble les N premiers octets de l'entry point.
    Requiert capstone (pip install capstone). Retourne None si absent.
    """
    try:
        import capstone
    except ImportError:
        return None

    try:
        import lief
        b = lief.parse(binary_path)
        if b is None:
            return None

        is_64 = False
        ep_va  = 0
        ep_rva = 0

        if isinstance(b, lief.PE.Binary):
            ep_rva  = b.optional_header.addressof_entrypoint
            ep_va   = int(getattr(b, "entrypoint", 0) or 0)
            if not ep_va and ep_rva:
                ep_va = b.optional_header.imagebase + ep_rva
            is_64 = b.header.machine == lief.PE.Header.MACHINE_TYPES.AMD64
            # Trouver la section contenant l'EP
            for s in b.sections:
                s_rva = s.virtual_address
                s_end = s_rva + max(s.virtual_size, s.size)
                if s_rva <= ep_rva < s_end:
                    offset = ep_rva - s_rva
                    raw = bytes(s.content)
                    data = raw[offset: offset + n_bytes]
                    break
            else:
                data = b""

        elif isinstance(b, lief.ELF.Binary):
            ep_va  = b.header.entrypoint
            is_64  = b.header.machine_type == lief.ELF.ARCH.x86_64
            for s in b.sections:
                s_va  = s.virtual_address
                s_end = s_va + s.size
                if s_va <= ep_va < s_end:
                    offset = ep_va - s_va
                    raw = bytes(s.content)
                    data = raw[offset: offset + n_bytes]
                    break
            else:
                data = b""
        else:
            return None

        if not data:
            return {"entry_point": hex(ep_va), "instructions": [], "note": "No data at EP"}

        arch = capstone.CS_ARCH_X86
        mode = capstone.CS_MODE_64 if is_64 else capstone.CS_MODE_32
        md   = capstone.Cs(arch, mode)
        md.detail = False

        instructions = []
        for insn in md.disasm(data, ep_va):
            instructions.append({
                "address": f"0x{insn.address:08x}",
                "mnemonic": insn.mnemonic,
                "op_str":   insn.op_str,
                "bytes":    insn.bytes.hex(),
            })
            if len(instructions) >= 30:
                break

        return {
            "entry_point":    hex(ep_va),
            "architecture":   "x86_64" if is_64 else "x86",
            "instructions":   instructions,
            "capstone_available": True,
        }

    except Exception as e:
        return {"error": str(e), "capstone_available": True}
