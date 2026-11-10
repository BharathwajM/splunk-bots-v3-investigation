#!/bin/bash
# Run one SPL search against the local BOTS Splunk and print CSV results.
# Usage: q.sh 'search index=botsv3 ... | stats ...' [max_rows]
# Reads the admin password from the root-only file; never prints it.
SPL="$1"
MAX="${2:-50}"
PW=$(cat /opt/bots/splunk-admin-password.txt)
curl -sk -u "admin:$PW" https://127.0.0.1:8089/services/search/jobs/export \
    --data-urlencode "search=$SPL" \
    -d earliest_time=0 -d output_mode=csv -d count=0 \
    | head -n "$((MAX + 1))"
