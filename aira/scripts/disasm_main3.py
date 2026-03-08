import pefile, capstone, struct

pe = pefile.PE('F:/Nouveau dossier (10)/data/uploads/crackme.exe')
IMAGEBASE = pe.OPTIONAL_HEADER.ImageBase
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

THUNKS = {
    0x1400029a0: 'fgets',
    0x140002960: 'strcspn',
    0x140002968: 'strlen',
    0x140002970: 'strncmp',
    0x1400029b0: 'puts',
    0x140002ae0: 'MessageBoxA',
    0x140001460: 'xor_encrypt',
    0x1400027e0: '?func',
    0x140002830: '?func2',
}

def va_to_data(va, pe):
    for section in pe.sections:
        s_va = IMAGEBASE + section.VirtualAddress
        if s_va <= va < s_va + section.Misc_VirtualSize:
            off = va - s_va
            return section.get_data()[off:]
    return None

# Desassembler depuis 0x1400014c8 (avant xor_encrypt call a 0x140001586)
start = 0x1400014c8
code = va_to_data(start, pe)
print(f"=== Desassemblage depuis 0x{start:x} ===\n")

# Aussi chercher des references a des strings dans .rdata
rdata_sec = None
for section in pe.sections:
    if section.Name.rstrip(b'\x00') == b'.rdata':
        rdata_sec = section
        rdata_va = IMAGEBASE + section.VirtualAddress
        rdata_data = section.get_data()
        break

def try_read_string(va, pe):
    data = va_to_data(va, pe)
    if data is None:
        return None
    end = data.find(b'\x00')
    if end == -1 or end > 100:
        return None
    s = data[:end]
    if all(0x20 <= b < 0x7f for b in s):
        return s.decode('ascii')
    return None

for i, insn in enumerate(md.disasm(code[:0x300], start)):
    annotation = ""
    # Resoudre les CALL vers des thunks connus
    if insn.mnemonic == 'call' and insn.op_str.startswith('0x'):
        target = int(insn.op_str, 16)
        name = THUNKS.get(target, '')
        if name:
            annotation = f"  ; -> {name}"
    # Detecter les LEA avec des adresses de strings
    if insn.mnemonic == 'lea' and 'rip' in insn.op_str:
        raw_off = insn.address - (IMAGEBASE + pe.sections[0].VirtualAddress)
        text_data = pe.sections[0].get_data()
        if 0 <= raw_off < len(text_data) - insn.size:
            try:
                rel = struct.unpack_from('<i', text_data, raw_off + 3)[0]
                str_va = insn.address + insn.size + rel
                s = try_read_string(str_va, pe)
                if s:
                    annotation = f'  ; -> "{s}"'
            except:
                pass
    # Detecter MOV avec valeur immediate (potentiellement cle XOR)
    if insn.mnemonic == 'mov' and 'byte ptr' in insn.op_str and '0x' in insn.op_str:
        annotation = f"  ; <-- byte value"

    print(f"  0x{insn.address:x}: {insn.mnemonic:<8} {insn.op_str:<40}{annotation}")
    if insn.mnemonic == 'ret' and i > 20:
        break
