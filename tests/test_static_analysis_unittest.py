import types
import unittest

import aira.static_analysis as sa


class TestStaticAnalysis(unittest.TestCase):
    def test_pe_entrypoint_va_and_rva(self):
        # Fake PE binary with optional_header.imagebase and addressof_entrypoint
        fake_bin = types.SimpleNamespace()
        fake_bin.optional_header = types.SimpleNamespace(
            imagebase=0x140000000,
            addressof_entrypoint=0x284d,
        )
        fake_bin.header = types.SimpleNamespace(machine_type=types.SimpleNamespace(name="AMD64"))
        fake_bin.sections = [types.SimpleNamespace(name=".text", virtual_address=0, virtual_size=0, size=0, characteristics=0x60000020)]
        fake_lib = types.SimpleNamespace(entries=[])
        fake_bin.imports = [types.SimpleNamespace(name="KERNEL32.dll", entries=[types.SimpleNamespace(name="ExitProcess", iat_address=0)])]

        called = {}

        def fake_parse(_):
            called["parse"] = True
            return fake_bin

        # Patch lief.parse used by load_binary
        orig_lief = sa.lief
        # Ensure isinstance(fake_bin, lief.ELF.Binary) is False for PE case
        class _DummyELFBinary:
            pass
        sa.lief = types.SimpleNamespace(parse=fake_parse, ELF=types.SimpleNamespace(Binary=_DummyELFBinary))
        try:
            info = sa.get_basic_info("C:/fake.exe")
        finally:
            sa.lief = orig_lief

        self.assertTrue(called.get("parse"))
        self.assertEqual(info.imagebase, 0x140000000)
        self.assertEqual(info.entrypoint, 0x140000000 + 0x284d)
        self.assertEqual(info.entrypoint_rva, 0x284d)
        self.assertEqual(info.format, "PE")
        self.assertEqual(info.sections[0]["flags"], 0x60000020)

    def test_elf_entrypoint_passthrough(self):
        fake_bin = types.SimpleNamespace(
            entrypoint=0x401000,
            imagebase=0,
            header=types.SimpleNamespace(machine="x86_64"),
            sections=[types.SimpleNamespace(name=".text", virtual_address=0, virtual_size=0, size=0, flags=6)],
            imports=[],
        )

        def fake_parse(_):
            return fake_bin

        orig_lief = sa.lief
        sa.lief = types.SimpleNamespace(parse=fake_parse, ELF=types.SimpleNamespace(Binary=type(fake_bin)))
        try:
            info = sa.get_basic_info("/bin/fake")
        finally:
            sa.lief = orig_lief

        self.assertEqual(info.entrypoint, 0x401000)
        self.assertIsNone(info.entrypoint_rva)
        self.assertEqual(info.format, "ELF")


if __name__ == "__main__":
    unittest.main()
