import importlib.util
import unittest
from pathlib import Path


def load_module(path: str):
    # Load a module from path and ensure it's visible in sys.modules
    import sys
    name = f"tests_dynamic_{Path(path).stem}"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)  # type: ignore[arg-type]
    return mod


class TestServices(unittest.TestCase):
    def test_symexec_server_routes(self):
        # Load solver to get the dataclass type for asdict()
        solver_mod = load_module("services/symexec_service/solver.py")
        server_mod = load_module("services/symexec_service/server.py")

        # Monkeypatch solve_path and build_cfg_dot
        def fake_solve_path(binary_path, addr_target, addr_avoid, stdin_len):
            return solver_mod.SolveResult(stdin=b"ABC", found_addr=0x1234, steps=1)

        def fake_build_cfg_dot(binary_path, addr):
            return "digraph G{}"

        server_mod.solve_path = fake_solve_path
        server_mod.build_cfg_dot = fake_build_cfg_dot

        # Call endpoints as plain functions
        out = server_mod.solve(server_mod.SolveIn(binary_path="X", addr_target="0x1"))
        self.assertEqual(out["stdin_hex"], b"ABC".hex())
        self.assertEqual(out["stdin_str"], "ABC")

        dot = server_mod.cfg(server_mod.CfgIn(binary_path="X", address="0x1"))
        self.assertIn("digraph", dot["dot"]) 

    def test_ai_service_server(self):
        server_mod = load_module("services/ai_service/server.py")

        class FakeProvider:
            def explain(self, code: str) -> str:
                return f"ok: {code[:5]}"

        server_mod.get_provider = lambda name: FakeProvider()
        out = server_mod.explain(server_mod.ExplainIn(code="mov eax, ebx"))
        self.assertTrue(out["explanation"].startswith("ok:"))


if __name__ == "__main__":
    unittest.main()
