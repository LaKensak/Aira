import pefile, capstone, struct

pe = pefile.PE('F:/Nouveau dossier (10)/data/uploads/crackme.exe')
IMAGEBASE = pe.OPTIONAL_HEADER.ImageBase
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

# Verifier les imports et leurs adresses reelles
print("=== Imports ===")
iat = {}
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in entry.imports:
        if imp.name:
            name = imp.name.decode('ascii', errors='replace')
            # imp.address est l'adresse VA de l'entree IAT
            iat[name] = imp.address
            if name in ('fgets', 'strncmp', 'puts', 'strlen', 'MessageBoxA', 'strcspn', 'IsDebuggerPresent'):
                print(f"  {name}: IAT VA=0x{imp.address:x}")

# La section .idata contient les thunks
# Cherchons les thunks pour fgets etc.
for section in pe.sections:
    sname = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
    if sname == '.idata':
        idata_va = IMAGEBASE + section.VirtualAddress
        idata_data = section.get_data()
        print(f"\n.idata @ 0x{idata_va:x}, taille={len(idata_data)}")

# Approche alternative: chercher des jmp [mem] dans .text (thunks)
text_sec = None
for section in pe.sections:
    if section.Name.rstrip(b'\x00') == b'.text':
        text_sec = section
        break

text_va = IMAGEBASE + text_sec.VirtualAddress
text_data = text_sec.get_data()

# Lister tous les CALL + JMP dans .text
print("\n=== CALL / JMP dans .text ===")
for insn in md.disasm(text_data, text_va):
    if insn.mnemonic in ('call', 'jmp') and 'ptr' in insn.op_str:
        # CALL QWORD PTR [RIP + x]
        raw_off = insn.address - text_va
        if raw_off >= 0 and raw_off + insn.size <= len(text_data):
            if insn.size >= 6:
                try:
                    rel = struct.unpack_from('<i', text_data, raw_off + 2)[0]
                    target = insn.address + insn.size + rel
                    # Chercher ce target dans IAT
                    for name, addr in iat.items():
                        if addr == target:
                            print(f"  0x{insn.address:x}: {insn.mnemonic} [{name}]  (IAT 0x{target:x})")
                            break
                    else:
                        if 0x140000000 <= target <= 0x140010000:
                            print(f"  0x{insn.address:x}: {insn.mnemonic} 0x{target:x}")
                except:
                    pass
    elif insn.mnemonic == 'call' and insn.op_str.startswith('0x'):
        target = int(insn.op_str, 16)
        if 0x140000000 <= target <= 0x140010000:
            print(f"  0x{insn.address:x}: call 0x{target:x}")
