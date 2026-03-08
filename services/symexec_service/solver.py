from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable
from pathlib import Path

import angr
import claripy
from angr import options as o
from angr import exploration_techniques as et


@dataclass
class SolveResult:
    stdin: bytes | None
    found_addr: int | None
    steps: int


def _parse_addr(s: str) -> int:
    s = s.lower().strip()
    return int(s, 16) if s.startswith("0x") else int(s)


def solve_path(
    binary_path: str,
    addr_target: str,
    addr_avoid: Iterable[str] = (),
    stdin_len: int = 64,
    *,
    input_mode: str = "stdin",
    argv_len: int = 32,
) -> SolveResult:
    if not Path(binary_path).exists():
        raise FileNotFoundError(f"Binary not found: {binary_path}")
    project = angr.Project(binary_path, auto_load_libs=False)
    addr_t = _parse_addr(addr_target)
    addrs_avoid = {_parse_addr(a) for a in addr_avoid}

    # Inputs: stdin vs argv[1]
    sym_stdin = claripy.BVS("stdin", 8 * stdin_len)
    if input_mode == "argv":
        sym_arg = claripy.BVS("argv1", 8 * argv_len)
        args = [binary_path, sym_arg]
    else:
        sym_arg = None
        args = [binary_path]

    # Initialize a full program state with proper runtime setup
    state = project.factory.full_init_state(args=args, stdin=sym_stdin)
    # Reduce explosion from unconstrained inputs/regs and illegal mem acceses
    state.options.update({
        o.ZERO_FILL_UNCONSTRAINED_MEMORY,
        o.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        o.STRICT_PAGE_ACCESS,
        o.LAZY_SOLVES,
        # o.UNICORN,  # enable if Unicorn is available to speed up
    })
    # Constrain to printable ASCII
    for byte in sym_stdin.chop(8):
        state.solver.add(byte >= 0x20, byte <= 0x7E)
    if sym_arg is not None:
        for byte in sym_arg.chop(8):
            state.solver.add(byte >= 0x20, byte <= 0x7E)

    simgr = project.factory.simulation_manager(state)
    # Add techniques to curb path explosion and merge straight-line code
    try:
        simgr.use_technique(et.Veritesting())
    except Exception:
        pass
    try:
        simgr.use_technique(et.LengthLimiter(max_length=800))  # cap path length
    except Exception:
        pass
    # Use Explorer to stop once a find state is discovered
    try:
        simgr.use_technique(et.Explorer(find=addr_t, avoid=list(addrs_avoid), num_find=1))
        simgr.run()
    except Exception:
        # Fallback to basic explore if techniques are unavailable
        simgr.explore(find=addr_t, avoid=list(addrs_avoid), num_find=1)

    if simgr.found:
        found = simgr.found[0]
        v = found.posix.dumps(0)
        return SolveResult(stdin=v, found_addr=addr_t, steps=len(simgr.active) + len(simgr.deadended))
    return SolveResult(stdin=None, found_addr=None, steps=len(simgr.active) + len(simgr.deadended))


def build_cfg_dot(binary_path: str, addr: str) -> str:
    project = angr.Project(binary_path, auto_load_libs=False)
    cfg = project.analyses.CFGFast(normalize=True)
    node = cfg.model.get_any_node(_parse_addr(addr))
    if node is None:
        # fallback: whole program graph
        return cfg.graph.to_agraph().to_string()
    subgraph = cfg.functions.get(node.function_address).transition_graph
    return subgraph.to_agraph().to_string()
