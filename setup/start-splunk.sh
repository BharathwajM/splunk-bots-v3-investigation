#!/bin/bash
# Start Splunk Enterprise in Docker (inside WSL) with the BOTS v3 app mounted.
# The admin password is generated once and kept in a root-only file; it is never printed.
set -e
PW_FILE=/opt/bots/splunk-admin-password.txt
if [ ! -s "$PW_FILE" ]; then
    umask 077
    printf 'Bots-%s\n' "$(openssl rand -base64 18 | tr -d '/+=')" > "$PW_FILE"
fi
SPLUNK_UID=$(docker run --rm --entrypoint id splunk/splunk:10.4 -u splunk)
SPLUNK_GID=$(docker run --rm --entrypoint id splunk/splunk:10.4 -g splunk)
chown -R "$SPLUNK_UID:$SPLUNK_GID" /opt/bots/apps/botsv3_data_set
docker rm -f bots-splunk >/dev/null 2>&1 || true
docker run -d --name bots-splunk --restart unless-stopped \
    -p 127.0.0.1:8000:8000 -p 127.0.0.1:8089:8089 \
    -e SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com \
    -e SPLUNK_START_ARGS=--accept-license \
    -e SPLUNK_PASSWORD="$(cat "$PW_FILE")" \
    -v /opt/bots/apps/botsv3_data_set:/opt/splunk/etc/apps/botsv3_data_set \
    splunk/splunk:10.4 >/dev/null
echo "started bots-splunk; admin password is in $PW_FILE"
