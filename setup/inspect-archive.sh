#!/bin/bash
# List the BOTS v3 archive without extracting it, and check every path is safe.
set -e
cd /opt/bots/download
tar -tzf botsv3_data_set.tgz > list.txt
echo "entries: $(wc -l < list.txt)"
echo "top-level folders:"
cut -d/ -f1 list.txt | sort | uniq -c
echo "absolute or ../ paths: $(grep -c -E '(^/|\.\./)' list.txt || true)"
echo "entry types (- file, d dir, l symlink, h hardlink):"
tar -tvzf botsv3_data_set.tgz | cut -c1 | sort | uniq -c
