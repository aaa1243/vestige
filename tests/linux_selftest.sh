#!/usr/bin/env bash
# Fakes a "cheated" Java game on Linux and checks the scanner catches it.
# Harmless: the fake game is a sleeping Python process named java.
#   usage: sudo bash tests/linux_selftest.sh [path-to-ForensicScanner]
set -euo pipefail
cd "$(dirname "$0")/.."
BIN="${1:-build/ForensicScanner}"
W=$(mktemp -d)
cat > "$W/fake.py" <<'PY'
import mmap, os, sys, time
p = sys.argv[1]
f = open(p, "r+b")
m = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ | mmap.PROT_EXEC, flags=mmap.MAP_PRIVATE)  # load the "library"
os.unlink(p)                      # then delete it from disk
time.sleep(60)
PY
head -c 8192 /dev/zero > "$W/payload.so"
( export JAVA_TOOL_OPTIONS="-javaagent:/tmp/agent.jar"
  exec -a java python3 "$W/fake.py" "$W/payload.so" -javaagent:/tmp/vape.jar ) &
PID=$!
sleep 1
"$BIN" --json "$W/out.json" || true
kill $PID 2>/dev/null || true
python3 tests/check_run.py "$W/out.json" \
    game_cmdline:DETECTION game_cmdline:WARNING game_environment:DETECTION game_memory_map:DETECTION
rm -rf "$W"
echo "SELF-TEST PASSED"
