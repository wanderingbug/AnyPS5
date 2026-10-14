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
eNrt1n1QFOcdB/DlOPB83UsCyU2ahrNuJqSJDifEkojJLdwli568CPgStfJ2pwhVOO5AGztyOQhumM1Y43SmmdixLzPp5I/WtIkB7OidVRA7tWhsarQx1qRWh7aiaVVA2D7P7nPncg39t5OZ78dxf8/ze55n93me2xd2uj0vmJKSuJhk7jlOr+lHJ/ffnFwul8JaaK8UQ//EGJjBTYqc9V6rWauz/gkxop80Ho3jUmnBzvonxE2seyzGxpnY9Q6k6f0SY+I0LFzC9eJMCTHGnLB+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAr5YKcZW4UqwQy8uk0N8tqRwnKUs2WTlOTb+cwXGH3iNdpI5IYAl/0KKUDraNTm9dKKkRxxk+o10br6TtaYsO8gcHlLRS2qdpkDQ72yZm+P/acUYbzhef9yjz96oc55EbhEp+VYS/zyVskvpdwjZ6Bv6JdqEtSY+7WdzP4gEWIywOsniJxWEW29h5drO4n8UDLEZYHGTxEovDLHLsPFYW7SxmsehksYTFShYbSTxCVsY5bjnOOAbU9Pcf5Tj5eEdku43sYzZP9/EdkjpC+pHi26ToUd7TlisdZr9Am0e+3Uvbe+hVxG66Z27HwGZuMxnxPTJCCh+zSopHqJSv08uI3bTzcvmG3qOG9SA/Er3muTn0QovuXTP7UXp0k6N4WCU6IsG0SVNeSJvkPrdDFX9Dh8QbezhtPm2HyLFHP9kcujyXYA2PmUTe82dJXidI3SfoPUKytu6XWMl+iPTjujNZ1eLjt6a8MZtkkkmG/O5p2nJN5EDuiDyXHBByh9b6+AwX6d8VECxSV7mQpZgXyqdvf7zkMbrX+Selrh1CppKWwRf0yRO3L4ZGf0h/u/zbfMGHhWq/dhn5Q/mEfMOzeIcg0SvOJVfk2zdNo5PwCJm0S5a74xa/i/7qLvm2RH8JUuzV1/bs1zmuI8K/fpKe92C70K7FvUIHXQW5uE1pHc/b10OX4Okip3LxBVGlOJnP/0Nebfc42VkXnx/x0Ivw+afoALvy4kTb6L7DJjYik4zoU1pNZNJto7W9E/qQo3RIJp8/7Ih0DPBFJ8gEi4ZDIzlkUr30wBecDE38nE6THviCm7fahRApOemibPINGuw99Eaia54/i+MCDwwFfLHnkyZtJOkY6KbV8A4hjQtkSmQ6lnDkavjOJ/yeSGjsR/TU+46Gx1528m/1OS0fOS19Tv5gn7vjc9rZI1hC0X+RCYdHSP9oeMymdf53vPMp0vmUKP9OlI955KuOAd+C2PV7zXQS9+pf8Dtdu4f7zbvtNqsqhY+mSKFRF1lm8IqkRqUULoVsdmiEPgPBY+TqfPsutoiamTTuTOm6lqzFN1h8+Z96DLNY/4Uem1lce0ePNSwuG9djGYuLTWYtFrD45DQ9ZrP4tVl6nEeiu+PCvQmdmaFP6GRRkhbPsNhbpsejLL6zWo+/YvHN9Xr8CYuvVetxD4vf3ajHV1jc3KBHP4svNemxmkSPvENY7aGPjEu+KZ+TlJw2idwS0b+kSkmnJWWWQndfil6xSEraDxy3hmy7JbVPCkX1bT6qhfDEI4E6JS81pP6adG696FDd8nChPDD0IJ/h5ArDUYsYjpikcL9FCquNgcNi6M7z5AdrtbqUtGfF8OW7Bf3mbzovOVW3UpIkhka1xhNu+aSxbegDPoM+a+S5qxXSXOS94aQvjxJPV61gc8tX6A1pF+V+kbznksgd7aIFk6iUC8miEhDMorJDSHErLiHVTRqmuUmDxa2sE6aL5DBDDB+bWazkHSmM/s1SrOR8IB8nb7Ohh7X5h/rpKtXjhSGVy6MvhIfJ8xga19Z6OUQeazpf/tW9pE5qLr32U1ob0cvv0/KoXu6n5Qm9/DEtq3p5iJTZvvCvjmsVNpqn79DY8LlaZUyvZJNjrOzWGu5qlc5C8mK4toIWyfwLFPNz4Ut38/vNmcOVdjU+xc71pJfWGDEb2/XLdi6Lt1qMrfo8Op+Jt84ytuoL63w83mo1tupL7UyPt6YZWmOL70yON9smNbN53ZiINT8yqZlN7NN4s31Ss75Nnb+PNwvGmbHWQ/HWzEmD2bbeHI81P2VovnaBpA3vpy7yQaLfWe2j4Omij5c8oqY/9hD9OGhfWGUa/VqcfTD+hT1NivJ1NX36Q9r71cq5yAOZK3WR29tFbm8n//rjI+RVL9/pkXft2iXxv4xK0avzFHObYna65JEnonxHKungiNC3ylup2ttldrse5+v167dIecl+WnaRTm+zwuxf0AK1wPC+P+3jL/yRxHMkfuLjWy76+MbP3iWVz0jlI1I5TyvnfXw9SdR/Tnqe9fGf/skn8hcu+fihyz6+iiR3/qydM9HXQ8RMWs5G6WFAWkL/Jgi+SfbFSj+ftIeabiMbcK3gjqqS3XkllWYOppMvjqpHKXSM/l25Vlwnrhe/LW5Y/1v81Q0A8P9H/ww3/s8aHJ7038T6JSeMS2LRmhD38/q/WL/KYf1frG5OiGJJ2dMbykorxBXuDS+sEJe7y7jmpmCV32tvqav1brVvbfRusfuq6hq8tbEGv3djXXPA609I+xrqGhNSjX5vs3dLgCQ4rvk71aXBet+2NUuXzxPn5XMVjdmLSsrrF+V+y03qBdya0qwtVS2NT64prNHag8u9dY5VzwS3F23V6iWby54OimWtNStztf7+ZfkVgY0r/IHqeq2+qcXREKxb6m8qped3cdvqs8SaKn9J9socre6tL2ppLl+40N+8htTdXJOjRiryvbi9xlOotVfkLCpqLa5b2ri9WTvf5kUrqsSKhipPS5ZWLy0uDVR7XU3N5Tna+Ia66poFjf5ttFBW411Jd6s4GDCkSqpqDTUxWFtn7FCTMPDeoIQB//v+offB/V+Sv2+K/Nwp8o4p8uIU+dIp8lVT5JumyIemyH9/ivyPp8i/O0U+OkWes+tPUKrhWaIshrzJkLca8sZn0WbIm42nN+RTDPlMQz7VkM8y5KcZ8rmGvMWQdxry0w15yZCfYciXGPIzDfnVhvwsQ77SkJ/9Je+d0wn18wn1fyTUx1h067cINydJb43VH9Dqpnj9G0n6Wy9WfypJf2vF9vKqVT9zbI2L2YVie5p5v56IrdXG4vPsfCWsf2yvt+kTiO9xLmufnjAeAAAAAOCr4D9pmz8o
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
