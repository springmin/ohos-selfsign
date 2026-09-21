#!/bin/sh
# Run a selfsign implementation over the reproduction fixtures.
#
#   sh run_repro.sh "python3 /path/to/selfsign.py" [outdir]
#   sh run_repro.sh "/path/to/selfsign-rs" [outdir]
#
# Reports, for each fixture: exit code, output size, md5, and whether the
# 20 KiB trailer survived (trail.elf) / whether e_shentsize=128 was accepted.
set -u
KIT="$(cd "$(dirname "$0")" && pwd)"
IMPL="$1"
OUT="${2:-$KIT/out}"
mkdir -p "$OUT"

check_trailer() {
    python3 - "$1" <<'EOF'
import sys
b = open(sys.argv[1], 'rb').read()
t = bytes((i * 7 + 13) & 0xFF for i in range(20 * 1024))
print('trailer: PRESENT (20480 B)' if t in b else 'trailer: LOST')
EOF
}

for f in base trail entsize128; do
    in="$KIT/fixtures/$f.elf"
    out="$OUT/$f.out"
    err="$OUT/$f.err"
    rm -f "$out" "$err"
    # shellcheck disable=SC2086
    $IMPL "$in" "$out" >/dev/null 2>"$err"
    rc=$?
    size=0; md5="-"
    if [ -f "$out" ]; then
        size=$(stat -c %s "$out")
        md5=$(md5sum "$out" | cut -d' ' -f1)
    fi
    printf '%-11s in=%-6s rc=%-3s out=%-6s md5=%s\n' "$f" "$(stat -c %s "$in")" "$rc" "$size" "$md5"
    if [ "$f" = "trail" ] && [ -f "$out" ]; then
        check_trailer "$out"
    fi
    if [ "$rc" != "0" ]; then
        printf '            stderr: %s\n' "$(head -1 "$err")"
    fi
done
