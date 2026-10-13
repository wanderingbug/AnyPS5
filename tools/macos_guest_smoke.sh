#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
build=${1:-$root/build}
guest=$build/macos-guest
rm -rf "$guest"
mkdir -p "$guest/libs"
python3 "$root/core/relinker/relinker/tests/macos/import_fixture.py" "$guest/import.elf"
"$build/core/relinker/relinker" --macos --skip-sce-module "$guest/import.elf" "$guest/eboot"
cp "$build/core/libs/libs/"*.prx "$guest/libs/"
echo "relinked guest"
set +e
NSUnbufferedIO=YES APS5_TRACE_START=1 APS5_TRACE_EXIT=1 "$guest/eboot"
guest_status=$?
set -e
if [ "$guest_status" -ne 0 ]; then
    echo "guest status $guest_status"
    debugger=$(command -v lldb || true)
    if [ -z "$debugger" ]; then debugger=$(xcrun --find lldb 2>/dev/null || true); fi
    if [ -n "$debugger" ]; then
        "$debugger" --batch -o run -o bt -o 'register read' -o 'disassemble -s $pc -c 16' -o quit -- "$guest/eboot" || true
    fi
    exit "$guest_status"
fi
echo "guest thread"
"$build/macos_guest_thread_self"
