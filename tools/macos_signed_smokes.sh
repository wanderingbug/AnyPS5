#!/bin/bash
set -euo pipefail
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
build=${1:-$root/build-integration}
case $build in
    /*) ;;
    *) build=$root/$build ;;
esac
mkdir -p "$build"
clang++ -std=c++20 -arch x86_64 -o "$build/macos_hardened_probe" "$root/tools/macos_hardened_probe.cpp"
"$root/tools/macos_sign_guest.sh" "$build/macos_hardened_probe"
"$build/macos_hardened_probe"

if [[ ! -x $root/tools/macos_guest_smoke.sh || ! -x $root/tools/macos_moltenvk_smoke.sh ]]; then
    echo "signed probe finished; guest smokes are on cursor/test-macos-integration-e22f" >&2
    exit 1
fi

"$root/tools/macos_guest_smoke.sh" "$build"
"$root/tools/macos_sign_guest.sh" "$build/macos-guest/eboot" "$build/macos-guest/libs"
guest_log=$build/macos-guest/signed.log
set +e
NSUnbufferedIO=YES APS5_TRACE_START=1 APS5_TRACE_EXIT=1 APS5_MIMALLOC=1 "$build/macos-guest/eboot" >"$guest_log" 2>&1
guest_status=$?
set -e
cat "$guest_log"
if grep -q 'dyld did not load libmimalloc.dylib' "$guest_log"; then
    echo "mimalloc: dyld ignored DYLD_INSERT_LIBRARIES"
elif grep -q 'APS5_MIMALLOC' "$guest_log"; then
    echo "mimalloc: restart log present"
else
    echo "mimalloc: no APS5_MIMALLOC log"
fi
if [[ $guest_status -ne 0 ]]; then
    echo "signed guest status $guest_status"
    exit "$guest_status"
fi

"$root/tools/macos_moltenvk_smoke.sh" "$build"
"$root/tools/macos_sign_guest.sh" "$build/macos-square/eboot" "$build/macos-square/libs"
"$root/tools/macos_sign_guest.sh" "$build/macos-square/eboot" "$build/macos-square/vk"
square=$build/macos-square
square_log=$square/signed.log
set +e
(
    cd "$square"
    DYLD_LIBRARY_PATH="$square/vk${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" \
        VK_DRIVER_FILES="$square/vk/MoltenVK_icd.json" \
        VK_ICD_FILENAMES="$square/vk/MoltenVK_icd.json" \
        APS5_SQUARE_INTERACTIVE=0 \
        APS5_SQUARE_FRAMES=1 \
        APS5_DUMP_FRAMES=1 \
        APS5_DUMP_SCALE=1 \
        APS5_NO_GPU_DUMP=1 \
        APS5_SYNC_FLIP=1 \
        APS5_MIMALLOC=1 \
        NSUnbufferedIO=YES \
        "$square/eboot"
) >"$square_log" 2>&1
square_status=$?
set -e
cat "$square_log"
if grep -q 'dyld did not load libmimalloc.dylib' "$square_log"; then
    echo "mimalloc: dyld ignored DYLD_INSERT_LIBRARIES"
elif grep -q 'APS5_MIMALLOC' "$square_log"; then
    echo "mimalloc: restart log present"
else
    echo "mimalloc: no APS5_MIMALLOC log"
fi
if [[ $square_status -ne 0 ]]; then
    echo "signed square status $square_status"
    exit "$square_status"
fi
python3 - "$square/frame_000.bmp" <<'PY'
import struct, sys
path = sys.argv[1]
data = open(path, "rb").read()
if data[:2] != b"BM":
    raise SystemExit("frame_000.bmp is not a BMP")
offset, = struct.unpack_from("<I", data, 10)
width, height = struct.unpack_from("<Ii", data, 18)
if width != 320 or height != -180:
    raise SystemExit(f"frame extent {width}x{height}, expected 320x-180")
pixels = data[offset:]
expected = width * 180 * 4
if len(pixels) < expected:
    raise SystemExit(f"frame pixels {len(pixels)}, expected {expected}")

def pixel(x, y):
    start = (y * width + x) * 4
    return pixels[start:start + 4]

background = bytes((0x20, 0x18, 0x10, 0xFF))
square = bytes((0x40, 0xE0, 0x40, 0xFF))
player = bytes((0xF0, 0x60, 0x20, 0xFF))
coin = bytes((0x30, 0xD0, 0xF0, 0xFF))
checks = [
    (0, 0, background), (39, 30, background), (40, 30, square), (67, 57, square), (68, 30, background),
    (200, 90, player), (211, 101, player), (212, 90, background),
    (16, 150, coin), (23, 157, coin), (15, 150, background),
    (260, 16, coin), (267, 23, coin), (268, 16, background),
]
for x, y, want in checks:
    got = pixel(x, y)
    if got != want:
        raise SystemExit(f"pixel {x},{y} is {got.hex()} expected {want.hex()}")
print(f"frame_000.bmp {width}x{-height} square ok")
PY
echo "signed square ok"
