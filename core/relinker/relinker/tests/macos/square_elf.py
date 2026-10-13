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
SHF_EXECINSTR = 4
SHT_NOBITS = 8
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
    executable = [(index, section) for index, section in allocated if section["flags"] & SHF_EXECINSTR]
    readonly = [(index, section) for index, section in allocated if section["flags"] & SHF_EXECINSTR == 0]
    cursor = 0x10000
    placed = {}
    pieces = []

    def place_sections(sections_to_place):
        nonlocal cursor
        for index, section in sections_to_place:
            cursor = align(cursor, section["align"])
            placed[index] = cursor
            pieces.append((cursor, section_bytes(blob, section)))
            cursor += section["size"]

    place_sections(executable)
    code_end = cursor
    cursor = align(cursor, 0x1000)
    ro_start = cursor
    place_sections(readonly)
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
    ro_end = dyn_va + dyn_size
    got_va = align(ro_end, 0x1000)
    got_size = len(imports) * 8
    nobits = [(index, section) for index, section in enumerate(sections) if section["flags"] & SHF_ALLOC and section["flags"] & SHF_EXECINSTR == 0 and section["kind"] == SHT_NOBITS and section["size"]]
    bss_cursor = align(got_va + got_size, 0x10000)
    bss_start = bss_cursor
    for index, section in nobits:
        bss_cursor = align(bss_cursor, max(section["align"], 1))
        placed[index] = bss_cursor
        bss_cursor += section["size"]
    bss_size = bss_cursor - bss_start
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
    ro_file_end = ro_end - 0x10000
    if len(image_rx) < ro_file_end:
        image_rx.extend(b"\0" * (ro_file_end - len(image_rx)))
    image_rx[str_va - 0x10000:str_va - 0x10000 + len(strings)] = strings
    for index, name_offset in enumerate(qualified, 1):
        struct.pack_into("<IBBHQQ", image_rx, sym_va - 0x10000 + index * 24, name_offset, 0x12, 0, 0, 0, 0)
    for index, name in enumerate(imports, 1):
        struct.pack_into("<QQq", image_rx, rela_va - 0x10000 + (index - 1) * 24, got_va + (index - 1) * 8, (index << 32) | 6, 0)
    for index, tag in enumerate(tags):
        struct.pack_into("<qQ", image_rx, dyn_va - 0x10000 + index * 16, *tag)
    image = bytearray(got_va + got_size)
    image[0x10000:0x10000 + len(image_rx)] = image_rx
    image[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    code_size = code_end - 0x10000
    ro_size = ro_end - ro_start
    phnum = 5 if bss_size else 4
    struct.pack_into("<HHIQQQIHHHHHH", image, 16, 3, 62, 1, entry, 64, 0, 0, 64, 56, phnum, 64, 0, 0)
    struct.pack_into("<IIQQQQQQ", image, 64, 1, 5, 0x10000, 0x10000, 0x10000, code_size, code_size, 0x1000)
    struct.pack_into("<IIQQQQQQ", image, 120, 1, 4, ro_start, ro_start, ro_start, ro_size, ro_size, 0x1000)
    struct.pack_into("<IIQQQQQQ", image, 176, 1, 6, got_va, got_va, got_va, got_size, got_size, 0x1000)
    struct.pack_into("<IIQQQQQQ", image, 232, 2, 4, dyn_va, dyn_va, dyn_va, dyn_size, dyn_size, 8)
    if bss_size:
        struct.pack_into("<IIQQQQQQ", image, 288, 1, 6, 0, bss_start, bss_start, 0, bss_size, 0x10000)
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
    begin = script.index(begin_mark)
    end = script.index(end_mark, begin + len(begin_mark)) + len(end_mark)
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
