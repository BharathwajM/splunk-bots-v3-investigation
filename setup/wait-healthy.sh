#!/bin/bash
# Wait up to 5 minutes for the Splunk container to report healthy.
for i in $(seq 1 60); do
    s=$(docker inspect -f '{{.State.Health.Status}}' bots-splunk)
    [ "$s" = healthy ] && break
    sleep 5
done
echo "$s after $((i * 5))s"
