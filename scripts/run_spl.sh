#!/bin/bash
# Run every .spl file in a folder against a local Splunk and save each result as CSV.
#
# Usage: run_spl.sh <folder-with-.spl-files> <output-folder>
#
# Needs: Splunk management port on 127.0.0.1:8089 and the admin password in
# $SPLUNK_PW_FILE (default /opt/bots/splunk-admin-password.txt). The password
# is read from the file and never printed.
# Text between ``` marks is a Splunk comment, so the .spl files paste straight
# into the Splunk search bar as well.
set -euo pipefail
IN="$1"
OUT="$2"
PW_FILE="${SPLUNK_PW_FILE:-/opt/bots/splunk-admin-password.txt}"
mkdir -p "$OUT"
for f in "$IN"/*.spl; do
    name=$(basename "$f" .spl)
    body=$(tr -d '\r' < "$f")
    case "$(sed '/^```/,/^```/d' <<<"$body" | grep -v '^\s*$' | head -c1)" in
        '|') search="$body" ;;
        *) search="search $body" ;;
    esac
    curl -sk -u "admin:$(cat "$PW_FILE")" \
        https://127.0.0.1:8089/services/search/jobs/export \
        --data-urlencode "search=$search" \
        -d earliest_time=0 -d output_mode=csv -d count=0 > "$OUT/$name.csv"
    rows=$(($(wc -l < "$OUT/$name.csv") - 1))
    [ "$rows" -lt 0 ] && rows=0
    printf '%-45s %6s rows\n' "$name" "$rows"
done
