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
"$guest/eboot"
echo "guest thread"
"$build/macos_guest_thread_self"
