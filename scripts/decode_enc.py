"""Decode PowerShell -EncodedCommand payloads offline and pull out the indicators.

Nothing is executed. Each payload is base64-decoded to UTF-16LE text. Any base64 string
literals inside it (Empire hides its C2 address this way) are decoded too. The script then
prints the URLs, user agents, URIs and cookies it finds.

Usage:
    python decode_enc.py payloads.csv        # CSV with a b64 column (output of queries/05b)
    python decode_enc.py --b64 SQBmACgA...   # one payload
    add --full to print the whole decoded script
"""
import argparse
import base64
import binascii
import csv
import re
import sys

URL = re.compile(r"https?://[^'\"\s;)+]+")
B64_LITERAL = re.compile(r"FromBase64String\(\s*'([A-Za-z0-9+/=]{8,})'\s*\)", re.IGNORECASE)
PATTERNS = {
    "user_agent": re.compile(r"\$u\s*=\s*'([^']+)'", re.IGNORECASE),
    "uri": re.compile(r"\$t\s*=\s*'([^']+)'", re.IGNORECASE),
    "cookie": re.compile(r'"Cookie"\s*,\s*"([^"]+)"', re.IGNORECASE),
}


def b64_text(value):
    """Decode base64 to UTF-16LE text, or None if it is not valid base64."""
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw.decode("utf-16-le", "replace")


def indicators(script):
    found = {"urls": set(URL.findall(script))}
    for literal in B64_LITERAL.findall(script):
        inner = b64_text(literal)
        if inner:
            found["urls"].update(URL.findall(inner) or [inner])
    for name, pattern in PATTERNS.items():
        found[name] = set(pattern.findall(script))
    return found


def report(label, payload, full):
    script = b64_text(payload)
    if script is None:
        print(f"== {label}: not valid base64")
        return
    print(f"== {label}: {len(script)} characters decoded")
    for name, values in indicators(script).items():
        for value in sorted(values):
            print(f"   {name:<10} {value}")
    if full:
        # Antivirus will flag this output as PowerShell Empire if it is saved to a file.
        print(script)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("csv", nargs="?", help="CSV file with a b64 column")
    parser.add_argument("--b64", help="a single base64 payload")
    parser.add_argument("--full", action="store_true", help="print the whole decoded script")
    args = parser.parse_args()
    if args.b64:
        report("payload", args.b64, args.full)
        return
    if not args.csv:
        parser.error("give a CSV file or --b64")
    seen = set()
    with open(args.csv, encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            payload = row.get("b64", "").strip()
            if not payload or payload in seen:
                continue
            seen.add(payload)
            label = " ".join(row.get(k, "") for k in ("_time", "host", "user") if row.get(k))
            report(label, payload, args.full)
    print(f"\n{len(seen)} unique payloads", file=sys.stderr)


if __name__ == "__main__":
    main()
