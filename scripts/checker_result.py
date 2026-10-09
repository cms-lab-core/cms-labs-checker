#!/usr/bin/env python3
"""Encode/decode the CMS Labs checker stdout contract using only stdlib."""
import argparse
import base64
import binascii
import hashlib
import json
import math
import re
import sys

PREFIX = b"CMS_LABS_CHECKER_RESULT_V1 "
MAX_RESULT_BYTES = 1024 * 1024
MAX_LOG_BYTES = 2 * 1024 * 1024
CHUNK_SIZE = 2048


def reject_constant(value):
    raise ValueError(f"invalid JSON constant: {value}")


def validate_result(payload):
    result = json.loads(payload, parse_constant=reject_constant)
    if not isinstance(result, dict):
        raise ValueError("result must be a JSON object")
    maximum, current = result.get("max_score"), result.get("current_score")
    for score in (maximum, current):
        if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score):
            raise ValueError("scores must be finite numbers")
    if maximum <= 0 or not 0 <= current <= maximum:
        raise ValueError("invalid checker score")
    display = result.get("result_display")
    if not isinstance(display, str) or not display.strip():
        raise ValueError("result_display is required")
    return result


def encode_result(payload):
    if not 0 < len(payload) <= MAX_RESULT_BYTES:
        raise ValueError("result exceeds 1 MiB limit")
    validate_result(payload)
    digest = hashlib.sha256(payload).hexdigest().encode()
    encoded = base64.b64encode(payload)
    return b"".join(
        PREFIX + digest + b" " + encoded[offset:offset + CHUNK_SIZE] + b"\n"
        for offset in range(0, len(encoded), CHUNK_SIZE)
    )


def decode_result(logs):
    if len(logs) > MAX_LOG_BYTES:
        raise ValueError("checker output exceeds 2 MiB limit")
    chunks, expected_hash, encoded_size = [], None, 0
    for line in logs.splitlines():
        if not line.startswith(PREFIX):
            if line.startswith(b"CMS_LABS_CHECKER_RESULT_"):
                raise ValueError("unknown result record")
            continue
        digest, separator, chunk = line[len(PREFIX):].partition(b" ")
        if not separator or not re.fullmatch(rb"[0-9a-f]{64}", digest) or not 0 < len(chunk) <= CHUNK_SIZE:
            raise ValueError("invalid result record")
        if expected_hash is not None and digest != expected_hash:
            raise ValueError("inconsistent result checksums")
        expected_hash = digest
        encoded_size += len(chunk)
        if encoded_size > ((MAX_RESULT_BYTES + 2) // 3) * 4:
            raise ValueError("result exceeds 1 MiB limit")
        chunks.append(chunk)
    if not chunks:
        raise ValueError("result missing from checker stdout")
    payload = base64.b64decode(b"".join(chunks), validate=True)
    if not 0 < len(payload) <= MAX_RESULT_BYTES:
        raise ValueError("result exceeds 1 MiB limit")
    if hashlib.sha256(payload).hexdigest().encode() != expected_hash:
        raise ValueError("incomplete or corrupted result")
    return validate_result(payload)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("encode", "decode"))
    args = parser.parse_args()
    try:
        limit = MAX_RESULT_BYTES if args.mode == "encode" else MAX_LOG_BYTES
        source = sys.stdin.buffer.read(limit + 1)
        if args.mode == "encode":
            sys.stdout.buffer.write(encode_result(source))
        else:
            result = decode_result(source)
            print(json.dumps(result, ensure_ascii=False, allow_nan=False))
    except (ValueError, binascii.Error, UnicodeError) as error:
        print(f"checker result error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
