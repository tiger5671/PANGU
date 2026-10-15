"""Join storage evidence from binaries belonging to one explicitly named firmware."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analysis.storage_graph import StorageGraph


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshots", nargs="+")
    parser.add_argument("--firmware-id", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--max-edges", type=int, default=10000)
    args = parser.parse_args()
    graph = StorageGraph.from_snapshots(args.snapshots, args.firmware_id, args.max_edges)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(graph.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Candidate storage channels: {len(graph.edges)}; gaps: {len(graph.gaps)}")


if __name__ == "__main__":
    main()
