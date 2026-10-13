#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
build=${1:-$root/build}
guest=$build/macos-square
moltenvk_version=v1.4.2
moltenvk_url=https://github.com/KhronosGroup/MoltenVK/releases/download/${moltenvk_version}/MoltenVK-macos.tar
moltenvk_member=MoltenVK/MoltenVK/dynamic/dylib/macOS/libMoltenVK.dylib
rm -rf "$guest"
mkdir -p "$guest/libs" "$guest/moltenvk"
if [ -n "${MOLTENVK_LIB:-}" ]; then
    cp "$MOLTENVK_LIB" "$guest/moltenvk/libMoltenVK.dylib"
elif [ -f /usr/local/lib/libMoltenVK.dylib ]; then
    cp /usr/local/lib/libMoltenVK.dylib "$guest/moltenvk/libMoltenVK.dylib"
    if [ -f /usr/local/lib/libvulkan.dylib ]; then
        cp /usr/local/lib/libvulkan.dylib "$guest/moltenvk/libvulkan.dylib"
    fi
else
    archive=$guest/MoltenVK-macos.tar
    curl -fL --retry 3 -o "$archive" "$moltenvk_url"
    tar -xf "$archive" -C "$guest" "$moltenvk_member"
    cp "$guest/$moltenvk_member" "$guest/moltenvk/libMoltenVK.dylib"
    rm -rf "$guest/MoltenVK" "$archive"
fi
file "$guest/moltenvk/libMoltenVK.dylib" | grep -q x86_64
python3 "$root/core/relinker/relinker/tests/macos/square_elf.py" "$guest/square.elf"
"$build/core/relinker/relinker" --macos --skip-sce-module "$guest/square.elf" "$guest/eboot"
cp "$build/core/libs/libs/"*.prx "$guest/libs/"
echo "relinked square"
cd "$guest"
set +e
DYLD_LIBRARY_PATH="$guest/moltenvk${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" \
    APS5_SQUARE_FRAMES=2 \
    APS5_DUMP_FRAMES=1 \
    APS5_DUMP_SCALE=1 \
    APS5_SYNC_FLIP=1 \
    NSUnbufferedIO=YES \
    "$guest/eboot"
guest_status=$?
set -e
if [ "$guest_status" -ne 0 ]; then
    echo "square status $guest_status"
    exit "$guest_status"
fi
python3 - "$guest/frame_000.bmp" <<'PY'
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
checks = [(0, 0, background), (39, 30, background), (40, 30, square), (67, 57, square), (68, 30, background)]
for x, y, want in checks:
    got = pixel(x, y)
    if got != want:
        raise SystemExit(f"pixel {x},{y} is {got.hex()} expected {want.hex()}")
print(f"frame_000.bmp {width}x{-height} square ok")
PY
