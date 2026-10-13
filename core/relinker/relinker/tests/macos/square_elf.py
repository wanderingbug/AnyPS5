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
    got_size = len(imports) * 8
    image = bytearray(got_va + got_size)
    image[0x10000:0x10000 + len(image_rx)] = image_rx
    image[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    code_size = code_end - 0x10000
    ro_size = ro_end - ro_start
    struct.pack_into("<HHIQQQIHHHHHH", image, 16, 3, 62, 1, entry, 64, 0, 0, 64, 56, 4, 64, 0, 0)
    struct.pack_into("<IIQQQQQQ", image, 64, 1, 5, 0x10000, 0x10000, 0x10000, code_size, code_size, 0x1000)
    struct.pack_into("<IIQQQQQQ", image, 120, 1, 4, ro_start, ro_start, ro_start, ro_size, ro_size, 0x1000)
    struct.pack_into("<IIQQQQQQ", image, 176, 1, 6, got_va, got_va, got_va, got_size, got_size, 0x1000)
    struct.pack_into("<IIQQQQQQ", image, 232, 2, 4, dyn_va, dyn_va, dyn_va, dyn_size, dyn_size, 8)
    return bytes(image), entry, imports


PAYLOAD = """
eNrt1W9sE+cdB/DHiaGmQB/T4jVaA/GKKzFtRXGgNNFK6yc5szM1EGNCRwsD4/jAcZr4bwhSNhyRSJwmb7SdxFa1EpX6vq1AiAAFu7SlUKlKEWk7qrUM1qpTtgFtBSVqe3ue+5MeXr03e7d9P5HueX7f53nuzvecnd3B8Mo6h4NY6snDxKiMY4D8uwBpJU5zRMyaYZtf3TYZg9MtcX836tRrc35V2zqT3NLa1+mR15xf1Q6a063WWldnXm+xx5hX3VbfhosAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD8f+lij7ENrIutj8rDf39rBiFyaYXsJkTzXGoihB0/xOfIo+X8w/SwqxQZL07N2rlU1sr+c7SpKNaX5j9drIzTw2dK8yNiSmacjwaK396e/WT0nLFcomsvnSTEQU4Q4uQnfoqfWFZP8bMWGvjV/kHF1UZ4eNJBRHdYH9/k8yr0SvkLulvyLZZPS75WcTmF7h7xBRxmp9PqbLU6aatTtDr7rM4Bq/Oy0ZF8Af3YqR+36se0sda60D6rc8DqvGx1ylZn3OpctDpXrQ6xrui2Ol6r08w7JzU+0X/df85/RvP8fiEh6huj5V3ikfzzDvEcMgunH0kf74ZLh/RPLp8wt64YVm8cFeNjImZHxLMO+s/0kB6+IsxXyHted8ulsM+rXhGXYUfE5NXqNWNGizmDb6645jP6Nb9ZMH3NqQXGNrg1D+VTxzSOb9ldt9y2mK9W1LBvTtCvHRMLp4fHiH5XxWP8OGac8n0xW/K52J6v6yQavhxWu30N7FV+dnJsMRGvW504nqjnx8lVtEniRcm5UFKv3fjTivvE6Wj7Ox2l+T+lHack9dMbHw1P/ZHo6ZeMdkyEtNPqKaZOMPVLpr4T/tmQr4GOuPgpfzPkmzOqDUblUt4XOGrcS5Tfy2j514/Qw2GfRA9LvmDx5vNH6/X3tePz4s3usW/4B5Zo+7WHunMudvxbXk3Oe+j5I3XGlIuKfn+ljkZWKjTKf5Djb4fiE3L8usyv5g76y5N306YACWllefg04V+s0PBXYofym0NtVxl9rhL0n5u8d5/Sftq539vADrpX7t20v679TWl/vRbSXgsNT4ldzZ8MtY0PXQi1nR2aCLW99qtxdr3iyJ/VVwUusoOBybcUYQltGtFfCrHV+icMqzc1z0Cj+JD6/p6dIz71gsbp/f1ho5iteR7n7Z4hn4vQ3/6Of0hJ/WpM3bt3r0xfqsiVzxaVnMWSMyCpN39coaN9fIK/rND+Gednize5f+5xo73fqK9c5/0VH4i+xCd9bHbmfqqPiufFx99V6IcTvP2At39W6MBHCk1ffoUXl3nxHi8uiOKCQlM8SP2Vzzyv0I/fVxj9kD/0yUsKjfFw94sjZfFt2FN28pHzFXE4I68QL13hWb4FLpl/X8QMzVO8h5C/HeTbyR/De7NF8gOe6PukeVK869c0z2wRDb8ufgKfYJvYZvZLtmXzKfyDAAAAAID/KXVmW1+VO8zWXdUeoMafNW/rVePPqp1VLeuMPrAlGuli64JbVq5jq4NRkssUYtmEN9bb2x/3KrFkb6LbygaS3Yl+b3860Vc1kE1sT+byiWxVrPQm01VROpvIJfryPDDkntwWKaSUwY2rVi9ii9pJS3s+tb011bLs8e16vTHS3BcbSP9kYyiu14XViaT/sbbCrjX9et2VXrq8c31qeeuDQV53kM6e6AMFFt0Z39Cq19lH27vy29dl89tSer1jwN9bSK7KZiLiehIZTDWzeCzbuXTDMr1OpNYM5Na3tGRzG3kdJBl/XF6j/HxXPBzSx7uWLV+zc21yVXpXTj9fz/J1MdbVGwsPNOt1ZG0kvy0hZXLrl+nr86EduUxPcya3Mqjfb29yW3xJOjsoOtF4YoN4omsLeVvUGeu2VazQnbRPiFct/G5R1YL//F6J9+fO78nn1ch/VCP318hZjTxSI4/VyDM18uEa+VM18hdq5K/UyCs18ndr5H+pkROv8U2dafvOCi5bXmfL3bbc/p1vsOVO++lt+QxbvtiWz7Tlzbb8Nlveastdtjxgy2fZctmW327LO235bFv+C1s+x5ZvteVzbfkOW36HLU/bcvo9v4fXquqpqnqu49b6HrMTNF5BssRhjFr1UofxK2zV7Q7j19iqww7j19R69hfdxgmtZ/KEeX5rDwJ3GoH1bBrM9hHzfEVzvrU35buMwNqTHeb4rKr1AAAAAAD/jX8BLJR73w==
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
