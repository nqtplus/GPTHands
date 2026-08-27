from __future__ import annotations

import argparse
import json
import tomllib
import uuid
from pathlib import Path


def load_project(root: Path) -> dict:
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    project = data["project"]
    dependencies = project.get("dependencies", [])
    if dependencies:
        # GPTHands currently has no runtime dependencies. Fail rather than emit
        # an incomplete SBOM if that changes without updating this generator.
        raise SystemExit("runtime dependencies detected; extend SBOM component parsing before release")
    return project


def build_bom(root: Path) -> dict:
    project = load_project(root)
    name = str(project["name"])
    version = str(project["version"])
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"https://github.com/nqtplus/GPTHands/{name}/{version}")
    component = {
        "type": "application",
        "bom-ref": f"pkg:pypi/{name}@{version}",
        "name": name,
        "version": version,
        "purl": f"pkg:pypi/{name}@{version}",
        "licenses": [{"license": {"id": "Apache-2.0"}}],
    }
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {"component": component},
        "components": [],
        "dependencies": [{"ref": component["bom-ref"], "dependsOn": []}],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, default=Path("dist/gpthands.cdx.json"))
    args = parser.parse_args()
    root = args.root.resolve()
    output = args.output if args.output.is_absolute() else root / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(build_bom(root), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
