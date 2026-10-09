#!/usr/bin/env python3
"""Validate the checker stdout protocol and smoke-check its score."""
import pathlib
import sys

from checker_result import MAX_LOG_BYTES, decode_result

def main(path: str) -> None:
    with pathlib.Path(path).open("rb") as source:
        result = decode_result(source.read(MAX_LOG_BYTES + 1))
    assert result["max_score"] == result["current_score"] == 2
    assert result["tasks"][0]["logs"][0]["namespace"] == "lab-ci"
    assert result["tasks"][0]["complete"] is True

if __name__ == "__main__":
    main(sys.argv[1])
