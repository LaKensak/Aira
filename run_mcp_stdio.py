import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aira.mcp_server import mcp
mcp.run(transport="stdio")
