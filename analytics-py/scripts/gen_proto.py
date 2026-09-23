import re
import sys
from pathlib import Path

from grpc_tools import protoc

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT.parent / "contracts"
OUT = ROOT / "src" / "analytics" / "gen"
PROTO = "analytics.proto"


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "__init__.py").write_text("", encoding="ascii")
    rc = protoc.main(
        [
            "grpc_tools.protoc",
            f"-I{CONTRACTS}",
            f"--python_out={OUT}",
            f"--pyi_out={OUT}",
            f"--grpc_python_out={OUT}",
            str(CONTRACTS / PROTO),
        ]
    )
    if rc != 0:
        print(f"protoc failed with {rc}", file=sys.stderr)
        return rc
    grpc_file = OUT / "analytics_pb2_grpc.py"
    text = grpc_file.read_text(encoding="utf-8")
    # protoc duz import uretiyor, paket icinde goreli olmali
    text = re.sub(r"^import analytics_pb2 as", "from . import analytics_pb2 as", text, flags=re.M)
    grpc_file.write_text(text, encoding="utf-8")
    print(f"generated python stubs in {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
