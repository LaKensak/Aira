import pefile, capstone, struct

pe = pefile.PE('F:/Nouveau dossier (10)/data/uploads/crackme.exe')
IMAGEBASE = pe.OPTIONAL_HEADER.ImageBase
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

def va_to_data(va, pe):
    for section in pe.sections:
        s_va = IMAGEBASE + section.VirtualAddress
        if s_va <= va < s_va + section.Misc_VirtualSize:
            off = va - s_va
            return section.get_data()[off:]
    return None

# Les fonctions dans la plage .text (0x140000600 - 0x140002200)
# D'apres les stabs, on a vu des adresses: 0x140001000, 0x140001150, etc.
# main est probablement une des premieres fonctions

# Desassembler les fonctions candidates
for func_va in [0x140001000, 0x140001150, 0x1400011b0, 0x1400016e0, 0x1400017d0, 0x1400017e0, 0x140001800, 0x140001890]:
    code = va_to_data(func_va, pe)
    if not code:
        continue
    print(f"\n=== Fonction @ 0x{func_va:x} ===")
    instrs = list(md.disasm(code[:0x200], func_va))
    for insn in instrs[:60]:
        print(f"  0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
        if insn.mnemonic == 'ret':
            break
