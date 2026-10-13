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
