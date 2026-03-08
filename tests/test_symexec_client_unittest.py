import types
import unittest

from aira.symexec.client import solve, SolveRequest


class TestSymexecClient(unittest.TestCase):
    def test_error_detail_is_surfaced(self):
        # Patch requests.post to simulate 400 with detail
        import aira.symexec.client as cli

        class FakeResp:
            ok = False
            status_code = 400
            reason = "Bad Request"
            text = "BAD"

            def json(self):
                return {"detail": "out of memory"}

        def fake_post(url, json, timeout):
            return FakeResp()

        orig_post = cli.requests.post
        cli.requests.post = fake_post
        try:
            with self.assertRaises(RuntimeError) as ctx:
                solve(SolveRequest(binary_path="X", addr_target="0x1"))
            self.assertIn("out of memory", str(ctx.exception))
        finally:
            cli.requests.post = orig_post

    def test_ok_returns_json(self):
        import aira.symexec.client as cli

        class FakeResp:
            ok = True

            def json(self):
                return {"ok": True}

        def fake_post(url, json, timeout):
            return FakeResp()

        orig_post = cli.requests.post
        cli.requests.post = fake_post
        try:
            data = solve(SolveRequest(binary_path="X", addr_target="0x1"))
            self.assertEqual(data["ok"], True)
        finally:
            cli.requests.post = orig_post


if __name__ == "__main__":
    unittest.main()

