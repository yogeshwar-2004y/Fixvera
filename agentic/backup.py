"""Operator-run SQLite backup and restore verification for the pilot."""
import argparse
import sqlite3
from pathlib import Path


def copy_verified(source: Path, target: Path):
    if not source.is_file():
        raise FileNotFoundError(source)
    if target.exists():
        raise FileExistsError(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with sqlite3.connect(source) as src, sqlite3.connect(target) as dst:
            src.backup(dst)
            result = dst.execute("PRAGMA integrity_check").fetchone()[0]
            if result != "ok":
                raise RuntimeError("Database integrity check failed: " + result)
    except Exception:
        target.unlink(missing_ok=True)
        raise
    return target


def main():
    parser = argparse.ArgumentParser(description="Copy and integrity-check a pilot SQLite database")
    parser.add_argument("source", type=Path)
    parser.add_argument("target", type=Path, help="Must not already exist")
    args = parser.parse_args()
    print(copy_verified(args.source, args.target))


if __name__ == "__main__":
    main()
