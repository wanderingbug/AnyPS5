"""Link square.c into a PS5-style guest ELF.

The image is produced on a Linux ELF toolchain and stored below so an Apple
clang, which emits Mach-O, can still write the same guest. Rebuild with
`python3 square_elf.py --rebuild` after editing square.c.
"""
import base64
import hashlib
import os
import struct
import subprocess
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nid import nid

SHF_ALLOC = 2
R_X86_64_PC32 = 2
R_X86_64_GOTPCREL = 9
R_X86_64_GOTPCRELX = 41
R_X86_64_REX_GOTPCRELX = 42
GOT_RELOCATIONS = {R_X86_64_GOTPCREL, R_X86_64_GOTPCRELX, R_X86_64_REX_GOTPCRELX}


def align(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def module_of(name):
    if name.startswith("sceVideoOut"):
        return "libSceVideoOut"
    if name.startswith("scePad"):
        return "libScePad"
    if name.startswith("sceAudioOut"):
        return "libSceAudioOut"
    return "libc"


def read_elf_object(blob):
    if blob[:4] != b"\x7fELF" or blob[4] != 2 or blob[5] != 1:
        raise SystemExit("square object is not ELF64")
    e_shoff, = struct.unpack_from("<Q", blob, 40)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", blob, 58)
    sections = []
    for index in range(e_shnum):
        offset = e_shoff + index * e_shentsize
        name, kind, flags, address, file_offset, size, link, info, alignment, entry = struct.unpack_from("<IIQQQQIIQQ", blob, offset)
        sections.append({
            "name": name, "kind": kind, "flags": flags, "offset": file_offset, "size": size,
            "link": link, "info": info, "align": alignment or 1, "entry": entry,
        })
    names = sections[e_shstrndx]
    def cstr(table, offset):
        end = blob.index(b"\0", table["offset"] + offset)
        return blob[table["offset"] + offset:end].decode()
    for section in sections:
        section["name"] = cstr(names, section["name"])
    return blob, sections


def section_bytes(blob, section):
    return blob[section["offset"]:section["offset"] + section["size"]]


def link_object(blob):
    blob, sections = read_elf_object(blob)
    by_index = {index: section for index, section in enumerate(sections)}
    allocated = [(index, section) for index, section in enumerate(sections) if section["flags"] & SHF_ALLOC and section["kind"] == 1 and section["size"]]
    cursor = 0x10000
    placed = {}
    pieces = []
    for index, section in allocated:
        cursor = align(cursor, section["align"])
        placed[index] = cursor
        pieces.append((cursor, section_bytes(blob, section)))
        cursor += section["size"]
    symtab = next(section for section in sections if section["kind"] == 2)
    strtab = by_index[symtab["link"]]
    symbols = []
    for offset in range(0, symtab["size"], 24):
        name, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", blob, symtab["offset"] + offset)
        end = blob.index(b"\0", strtab["offset"] + name)
        symbols.append({
            "name": blob[strtab["offset"] + name:end].decode(),
            "info": info, "shndx": shndx, "value": value,
        })
    guest_start = next(symbol for symbol in symbols if symbol["name"] == "guest_start")
    entry = placed[guest_start["shndx"]] + guest_start["value"]
    imports = []
    got_of = {}
    for symbol in symbols:
        if symbol["shndx"] == 0 and symbol["name"] and symbol["name"] not in got_of:
            got_of[symbol["name"]] = len(imports)
            imports.append(symbol["name"])
    image_rx = bytearray(b"\0" * (cursor - 0x10000))
    for address, data in pieces:
        start = address - 0x10000
        image_rx[start:start + len(data)] = data
    relocations = []
    for section in sections:
        if section["kind"] != 4:
            continue
        target = by_index[section["info"]]
        if target["flags"] & SHF_ALLOC == 0:
            continue
        for offset in range(0, section["size"], 24):
            place, info, addend = struct.unpack_from("<QQq", blob, section["offset"] + offset)
            relocations.append((by_index[section["info"]], place, info & 0xffffffff, info >> 32, addend))
    modules = []
    for name in imports:
        module = module_of(name)
        if module not in modules:
            modules.append(module)
    letters = "BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-"
    module_letter = {module: letters[index] for index, module in enumerate(modules)}
    strings = bytearray(b"\0")
    def add_string(text):
        offset = len(strings)
        strings.extend(text.encode() + b"\0")
        return offset
    qualified = []
    for name in imports:
        qualified.append(add_string(nid(name) + "#A#" + module_letter[module_of(name)]))
    needed = [(module + ".prx", add_string(module + ".prx")) for module in modules]
    declared = [(module, add_string(module)) for module in modules]
    sym_size = (len(imports) + 1) * 24
    rela_size = len(imports) * 24
    tags = [(1, offset) for _, offset in needed]
    tags += [(0x61000045, (index << 48) | offset) for index, (_, offset) in enumerate(declared, 1)]
    tags += [(5, 0), (10, len(strings)), (6, 0), (11, 24), (0x6100003f, sym_size), (7, 0), (8, rela_size), (9, 24), (0, 0)]
    dyn_size = len(tags) * 16
    meta = align(cursor, 8)
    str_va = meta
    sym_va = align(str_va + len(strings), 8)
    rela_va = align(sym_va + sym_size, 8)
    dyn_va = align(rela_va + rela_size, 8)
    rx_end = dyn_va + dyn_size
    got_va = align(rx_end, 0x1000)
    for index, (tag, value) in enumerate(tags):
        if tag == 5:
            tags[index] = (tag, str_va)
        elif tag == 6:
            tags[index] = (tag, sym_va)
        elif tag == 7:
            tags[index] = (tag, rela_va)
    def place_address(section, offset):
        return placed[next(index for index, item in enumerate(sections) if item is section)] + offset
    for section, place, kind, symbol_index, addend in relocations:
        address = place_address(section, place)
        file_at = address - 0x10000
        symbol = symbols[symbol_index]
        if kind == R_X86_64_PC32:
            if symbol["shndx"] == 0:
                raise SystemExit("PC32 relocation to " + symbol["name"])
            target = placed[symbol["shndx"]] + symbol["value"] + addend - address
            image_rx[file_at:file_at + 4] = struct.pack("<i", target)
        elif kind in GOT_RELOCATIONS:
            slot = got_va + got_of[symbol["name"]] * 8
            target = slot + addend - address
            image_rx[file_at:file_at + 4] = struct.pack("<i", target)
        else:
            raise SystemExit(f"unsupported relocation {kind} for {symbol['name']}")
    rx_size = rx_end - 0x10000
    if len(image_rx) < rx_size:
        image_rx.extend(b"\0" * (rx_size - len(image_rx)))
    image_rx[str_va - 0x10000:str_va - 0x10000 + len(strings)] = strings
    for index, name_offset in enumerate(qualified, 1):
        struct.pack_into("<IBBHQQ", image_rx, sym_va - 0x10000 + index * 24, name_offset, 0x12, 0, 0, 0, 0)
    for index, name in enumerate(imports, 1):
        struct.pack_into("<QQq", image_rx, rela_va - 0x10000 + (index - 1) * 24, got_va + (index - 1) * 8, (index << 32) | 6, 0)
    for index, tag in enumerate(tags):
        struct.pack_into("<qQ", image_rx, dyn_va - 0x10000 + index * 16, *tag)
    got_size = len(imports) * 8
    image = bytearray(got_va + got_size)
    image[0x10000:0x10000 + len(image_rx)] = image_rx
    image[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", image, 16, 3, 62, 1, entry, 64, 0, 0, 64, 56, 3, 64, 0, 0)
    struct.pack_into("<IIQQQQQQ", image, 64, 1, 5, 0x10000, 0x10000, 0x10000, rx_size, rx_size, 0x1000)
    struct.pack_into("<IIQQQQQQ", image, 120, 1, 6, got_va, got_va, got_va, got_size, got_size, 0x1000)
    struct.pack_into("<IIQQQQQQ", image, 176, 2, 4, dyn_va, dyn_va, dyn_va, dyn_size, dyn_size, 8)
    return bytes(image), entry, imports


PAYLOAD = """
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
"""


def payload_bytes():
    if not PAYLOAD.strip():
        raise SystemExit("square guest image is empty; run square_elf.py --rebuild")
    return zlib.decompress(base64.b64decode(PAYLOAD))


def rebuild(path):
    source = os.path.join(os.path.dirname(os.path.abspath(__file__)), "square.c")
    object_path = path + ".o"
    subprocess.check_call([
        "clang", "-c", "-O2", "-fPIC", "-fno-plt", "-ffreestanding", "-fno-builtin",
        "-fno-stack-protector", "-fno-asynchronous-unwind-tables", "-fcf-protection=none",
        "-mno-red-zone", "-o", object_path, source,
    ])
    image, entry, imports = link_object(open(object_path, "rb").read())
    encoded = base64.b64encode(zlib.compress(image, 9)).decode()
    script = open(__file__, "r", encoding="utf-8").read()
    begin_mark = "PAYLOAD = \"\"\"\n"
    end_mark = "\"\"\"\n"
    begin = script.index(begin_mark) + len(begin_mark)
    end = script.index(end_mark, begin)
    wrapped = "PAYLOAD = \"\"\"\n" + encoded + "\n\"\"\"\n"
    open(__file__, "w", encoding="utf-8").write(script[:begin] + wrapped + script[end:])
    print(f"entry 0x{entry:x} imports {len(imports)} bytes {len(image)} sha256 {hashlib.sha256(image).hexdigest()}")
    return image


def main(argv):
    if len(argv) == 2 and argv[1] == "--rebuild":
        rebuild(os.path.join(os.path.dirname(os.path.abspath(__file__)), "square.elf"))
        return
    if len(argv) != 2:
        raise SystemExit("usage: square_elf.py OUTPUT | square_elf.py --rebuild")
    open(argv[1], "wb").write(payload_bytes() if argv[1] != "-" else payload_bytes())


if __name__ == "__main__":
    main(sys.argv)
