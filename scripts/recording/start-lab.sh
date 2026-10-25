#!/usr/bin/env bash
# Source this file from the recorded real shell to export the actual listener URLs.
set -o pipefail
source ./private.env
export PATH="$PWD/node_modules/.bin:$PATH"
for instance in a b; do
  if [ -f "$instance.pid" ] && kill -0 "$(cat "$instance.pid")" 2>/dev/null; then
    kill -TERM "$(cat "$instance.pid")"
    for attempt in {1..50}; do kill -0 "$(cat "$instance.pid")" 2>/dev/null || break; sleep 0.1; done
  fi
  node node_modules/@cloud-api-shield/shield/dist/packages/cli/main.js serve "$instance.yaml" >"$instance.events.jsonl" 2>"$instance.startup.log" &
  echo $! > "$instance.pid"
  for attempt in {1..100}; do grep -q 'listening at http:' "$instance.startup.log" && break; sleep 0.1; done
  grep -q 'listening at http:' "$instance.startup.log" || { cat "$instance.startup.log"; return 1; }
done
export A="$(sed -n 's/.*listening at \(http:\/\/127\.0\.0\.1:[0-9]*\);.*/\1/p' a.startup.log)"
export B="$(sed -n 's/.*listening at \(http:\/\/127\.0\.0\.1:[0-9]*\);.*/\1/p' b.startup.log)"
export H='Host: api.vm.test'
printf 'Runtime A: %s\nRuntime B: %s\nCanonical Host: api.vm.test\n' "$A" "$B"
