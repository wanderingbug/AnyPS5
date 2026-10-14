#include "prx/libc/include/exceptions/Unwind.hpp"
#include "prx/libc/include/exceptions/Runtime.hpp"
#include "prx/libc/include/specifics/linux/ElfTypes.hpp"
#include "prx/libc/src/specifics/x86_64/RegisterContext.cpp"

#if defined(__linux__)
#include <dlfcn.h>
#endif
#ifdef _WIN32
#include <windows.h>
#include <algorithm>
#include <array>
#include <map>
#include <mutex>
#include <utility>
#include <vector>
#endif
#ifdef __APPLE__
#include <dlfcn.h>
#include <mach-o/getsect.h>
#include <mach-o/loader.h>
#endif

#if defined(__linux__) || defined(_WIN32) || defined(__APPLE__)

extern "C" _Unwind_Reason_Code __gxx_personality_v0(int, _Unwind_Action, std::uint64_t, _Unwind_Exception*, _Unwind_Context*);
extern "C" _Unwind_Reason_Code __gcc_personality_v0(int, _Unwind_Action, std::uint64_t, _Unwind_Exception*, _Unwind_Context*);

namespace LibcUnwind {
_Unwind_Reason_Code CallPersonality(Word personality, _Unwind_Action actions, _Unwind_Exception* exception, _Unwind_Context* context) {
#ifdef _WIN32
    const auto* code = reinterpret_cast<const Byte*>(personality);
    if (code[0] == 0xff && code[1] == 0x25) {
        std::int32_t displacement;
        std::memcpy(&displacement, code + 2, 4);
        std::memcpy(&personality, code + 6 + displacement, sizeof(personality));
    }
#endif
    if (personality == reinterpret_cast<Word>(__gxx_personality_v0_nid_postfix) || personality == reinterpret_cast<Word>(__gxx_personality_v0))
        return __gxx_personality_v0_nid_postfix(1, actions, exception->exception_class, exception, context);
    if (personality == reinterpret_cast<Word>(__gcc_personality_v0_nid_postfix) || personality == reinterpret_cast<Word>(__gcc_personality_v0))
        return __gcc_personality_v0_nid_postfix(1, actions, exception->exception_class, exception, context);
#ifdef __APPLE__
    Dl_info info {};
    if (dladdr(reinterpret_cast<void*>(personality), &info) && info.dli_sname) {
        if (std::strstr(info.dli_sname, "gxx_personality_v0"))
            return __gxx_personality_v0_nid_postfix(1, actions, exception->exception_class, exception, context);
        if (std::strstr(info.dli_sname, "gcc_personality_v0"))
            return __gcc_personality_v0_nid_postfix(1, actions, exception->exception_class, exception, context);
    }
#endif
    return (actions & _UA_SEARCH_PHASE) ? _URC_FATAL_PHASE1_ERROR : _URC_FATAL_PHASE2_ERROR;
}
struct Lookup { Word pc; const Byte* fde {}; Word text {}; Word data {}; };

#if defined(__linux__) || defined(__APPLE__)
int FindFrame(dl_phdr_info* info, std::size_t, void* argument) {
    auto& query = *static_cast<Lookup*>(argument);
    const Byte* header = nullptr;
    bool contains = false;
    for (unsigned i = 0; i < info->dlpi_phnum; ++i) {
        const auto& ph = info->dlpi_phdr[i];
        Word start = info->dlpi_addr + ph.p_vaddr;
        if (ph.p_type == PT_LOAD && query.pc >= start && query.pc - start < ph.p_memsz) contains = true;
        if (ph.p_type == PT_GNU_EH_FRAME) header = reinterpret_cast<const Byte*>(start);
        if (ph.p_type == PT_LOAD && (ph.p_flags & PF_X)) query.text = start;
        if (ph.p_type == PT_LOAD && (ph.p_flags & PF_W)) query.data = start;
    }
    if (!contains || !header || header[0] != 1) return 0;
    const Byte* p = header + 4;
    Encoded(p, header[1], Word(header));
    Word count = Encoded(p, header[2]);
    if (header[3] == 255) return 1;
    unsigned width = EncodingSize(header[3]);
    const Byte* table = p;
    Word lo = 0, hi = count;
    while (lo < hi) {
        Word mid = lo + (hi - lo) / 2;
        p = table + mid * width * 2;
        Word begin = Encoded(p, header[3], Word(header));
        if (begin <= query.pc) lo = mid + 1; else hi = mid;
    }
    if (lo) {
        p = table + (lo - 1) * width * 2 + width;
        query.fde = reinterpret_cast<const Byte*>(Encoded(p, header[3], Word(header)));
    }
    return 1;
}

#endif

struct Frame {
    const Byte* cieBegin {};
    const Byte* cieEnd {};
    const Byte* begin {};
    const Byte* end {};
    Word start {}, length {}, personality {}, lsda {};
    Word codeAlign {};
    std::intptr_t dataAlign {};
    unsigned returnRegister {};
    bool signal {};
    bool useCompact {};
    std::uint32_t compactEncoding {};
    Word functionStart {};
};

bool DecodeRange(Frame& frame, const Lookup& query, const Byte*& p, const char*& augmentation, Byte& lsdaEncoding) {
    if (!query.fde) return false;
    p = query.fde;
    auto length = Read<std::uint32_t>(p);
    if (!length || length == 0xffffffff) return false;
    frame.end = p + length;
    const Byte* ciePointer = p;
    auto cieOffset = Read<std::uint32_t>(p);
    const Byte* cie = ciePointer - cieOffset;
    const Byte* c = cie;
    auto cieLength = Read<std::uint32_t>(c);
    frame.cieEnd = c + cieLength;
    if (Read<std::uint32_t>(c) != 0) return false;
    Byte version = *c++;
    if (version != 1 && version != 3 && version != 4) return false;
    augmentation = reinterpret_cast<const char*>(c);
    while (*c++) {}
    if (version == 4 && (*c++ != sizeof(Word) || *c++ != 0)) return false;
    frame.codeAlign = Uleb(c);
    frame.dataAlign = Sleb(c);
    frame.returnRegister = version == 1 ? *c++ : Uleb(c);
#ifdef _WIN32
    if (frame.returnRegister >= 17 && frame.returnRegister != 32) return false;
#else
    if (frame.returnRegister >= 17) return false;
#endif
    Byte pointerEncoding = 0;
    lsdaEncoding = 255;
    if (*augmentation == 'z') {
        Word size = Uleb(c);
        const Byte* end = c + size;
        for (const char* a = augmentation + 1; *a; ++a) {
            switch (*a) {
            case 'R': pointerEncoding = *c++; break;
            case 'L': lsdaEncoding = *c++; break;
            case 'P': { Byte encoding = *c++; frame.personality = Encoded(c, encoding, query.data, 0, query.text); break; }
            case 'S': frame.signal = true; break;
            default: return false;
            }
        }
        c = end;
    } else if (*augmentation) return false;
    frame.cieBegin = c;
    frame.start = Encoded(p, pointerEncoding, query.data, 0, query.text);
    frame.length = Encoded(p, pointerEncoding & 15);
    return true;
}

bool DecodeCandidate(_Unwind_Context& context, Frame& frame, const Lookup& query) {
    const Byte* p;
    const char* augmentation;
    Byte lsdaEncoding;
    if (!DecodeRange(frame, query, p, augmentation, lsdaEncoding)) return false;
    if (query.pc < frame.start || query.pc - frame.start >= frame.length) return false;
    if (*augmentation == 'z') {
        Word size = Uleb(p);
        const Byte* end = p + size;
        if (lsdaEncoding != 255) frame.lsda = Encoded(p, lsdaEncoding, query.data, frame.start, query.text);
        p = end;
    }
    frame.begin = p;
    context.region = frame.start;
    context.lsda = frame.lsda;
    context.personality = frame.personality;
    context.textBase = query.text;
    context.dataBase = query.data;
    return true;
}

#ifdef _WIN32
using FrameIndex = std::vector<std::pair<Word, const Byte*>>;
using ImageKey = std::array<Word, 6>;

const FrameIndex& IndexFrames(const ImageKey& key, const Byte* begin, const Byte* end) {
    static std::mutex mutex;
    static std::map<ImageKey, FrameIndex> indexes;
    std::lock_guard lock(mutex);
    const auto [entry, inserted] = indexes.try_emplace(key);
    auto& index = entry->second;
    if (!inserted) return index;
    const Byte* p = begin;
    while (end - p >= 8) {
        const Byte* record = p;
        const auto length = Read<std::uint32_t>(p);
        if (!length) continue;
        if (length == 0xffffffff || length < 4 || Word(end - p) < length) break;
        const Byte* next = p + length;
        if (Read<std::uint32_t>(p)) {
            Frame candidate {};
            const Byte* cursor;
            const char* augmentation;
            Byte lsdaEncoding;
            if (DecodeRange(candidate, Lookup {0, record}, cursor, augmentation, lsdaEncoding))
                index.emplace_back(candidate.start, record);
        }
        p = next;
    }
    std::sort(index.begin(), index.end());
    return index;
}
#endif

#ifdef __APPLE__
std::uint32_t Section32(const Byte* data, unsigned long size, unsigned long offset, bool& ok) {
    std::uint32_t value = 0;
    if (!ok || offset > size || size - offset < 4) { ok = false; return 0; }
    std::memcpy(&value, data + offset, 4);
    return value;
}

bool AppleCompact(_Unwind_Context& context, Frame& frame, Lookup& query) {
    Dl_info image {};
    if (!dladdr(reinterpret_cast<void*>(query.pc), &image) || !image.dli_fbase) return false;
    const auto base = reinterpret_cast<Word>(image.dli_fbase);
    if (query.pc < base) return false;
    unsigned long infoSize = 0;
    const auto* info = getsectiondata(static_cast<const mach_header_64*>(image.dli_fbase), "__TEXT", "__unwind_info", &infoSize);
    if (!info || infoSize < 28) return false;
    bool ok = true;
    if (Section32(info, infoSize, 0, ok) != 1 || !ok) return false;
    const auto commonOffset = Section32(info, infoSize, 4, ok);
    const auto commonCount = Section32(info, infoSize, 8, ok);
    const auto personalityOffset = Section32(info, infoSize, 12, ok);
    const auto personalityCount = Section32(info, infoSize, 16, ok);
    const auto indexOffset = Section32(info, infoSize, 20, ok);
    const auto indexCount = Section32(info, infoSize, 24, ok);
    if (!ok || indexCount < 2) return false;
    const auto target = static_cast<std::uint32_t>(query.pc - base);
    std::uint32_t low = 0, high = indexCount;
    const auto last = indexCount - 1;
    while (low < high) {
        const auto mid = low + (high - low) / 2;
        const auto start = Section32(info, infoSize, indexOffset + static_cast<unsigned long>(mid) * 12u, ok);
        if (!ok) return false;
        if (start <= target) {
            const auto follows = mid == last ? target : Section32(info, infoSize, indexOffset + static_cast<unsigned long>(mid + 1) * 12u, ok);
            if (!ok) return false;
            if (mid == last || follows > target) { low = mid; break; }
            low = mid + 1;
        } else high = mid;
    }
    if (!ok || low >= last) return false;
    const auto pageFunction = Section32(info, infoSize, indexOffset + static_cast<unsigned long>(low) * 12u, ok);
    const auto nextFunction = Section32(info, infoSize, indexOffset + static_cast<unsigned long>(low + 1) * 12u, ok);
    const auto pageOffset = Section32(info, infoSize, indexOffset + static_cast<unsigned long>(low) * 12u + 4u, ok);
    const auto lsdaOffset = Section32(info, infoSize, indexOffset + static_cast<unsigned long>(low) * 12u + 8u, ok);
    const auto lsdaEnd = Section32(info, infoSize, indexOffset + static_cast<unsigned long>(low + 1) * 12u + 8u, ok);
    if (!ok || pageOffset == 0) return false;
    const auto pageKind = Section32(info, infoSize, pageOffset, ok);
    const auto pagePacked = Section32(info, infoSize, pageOffset + 4u, ok);
    if (!ok) return false;
    const auto entryOffset = pagePacked & 0xffffu;
    const auto entryCount = pagePacked >> 16;
    if (entryCount == 0) return false;
    std::uint32_t encoding = 0;
    Word funcStart = 0, funcEnd = 0;
    if (pageKind == 2) {
        low = 0;
        high = entryCount;
        while (low < high) {
            const auto mid = low + (high - low) / 2;
            const auto start = Section32(info, infoSize, pageOffset + entryOffset + static_cast<unsigned long>(mid) * 8u, ok);
            if (!ok) return false;
            if (start <= target) {
                if (mid + 1 == entryCount) { low = mid; break; }
                const auto follows = Section32(info, infoSize, pageOffset + entryOffset + static_cast<unsigned long>(mid + 1) * 8u, ok);
                if (!ok) return false;
                if (follows > target) { low = mid; break; }
                low = mid + 1;
            } else high = mid;
        }
        if (low >= entryCount) return false;
        const auto start = Section32(info, infoSize, pageOffset + entryOffset + static_cast<unsigned long>(low) * 8u, ok);
        encoding = Section32(info, infoSize, pageOffset + entryOffset + static_cast<unsigned long>(low) * 8u + 4u, ok);
        if (!ok) return false;
        funcStart = base + start;
        funcEnd = low + 1 < entryCount ? base + Section32(info, infoSize, pageOffset + entryOffset + static_cast<unsigned long>(low + 1) * 8u, ok) : base + nextFunction;
    } else if (pageKind == 3) {
        const auto encodingPacked = Section32(info, infoSize, pageOffset + 8u, ok);
        if (!ok) return false;
        const auto encodingsOffset = encodingPacked & 0xffffu;
        const auto pageTarget = target - pageFunction;
        const auto pageLast = entryCount - 1;
        low = 0;
        high = entryCount;
        while (low < high) {
            const auto mid = low + (high - low) / 2;
            const auto entry = Section32(info, infoSize, pageOffset + entryOffset + static_cast<unsigned long>(mid) * 4u, ok);
            if (!ok) return false;
            const auto start = entry & 0x00ffffffu;
            if (start <= pageTarget) {
                if (mid == pageLast) { low = mid; break; }
                const auto follows = Section32(info, infoSize, pageOffset + entryOffset + static_cast<unsigned long>(mid + 1) * 4u, ok) & 0x00ffffffu;
                if (!ok) return false;
                if (follows > pageTarget) { low = mid; break; }
                low = mid + 1;
            } else high = mid;
        }
        if (low >= entryCount) return false;
        const auto entry = Section32(info, infoSize, pageOffset + entryOffset + static_cast<unsigned long>(low) * 4u, ok);
        if (!ok) return false;
        funcStart = base + pageFunction + (entry & 0x00ffffffu);
        if (low < pageLast) funcEnd = base + pageFunction + (Section32(info, infoSize, pageOffset + entryOffset + static_cast<unsigned long>(low + 1) * 4u, ok) & 0x00ffffffu);
        else funcEnd = base + nextFunction;
        const auto encodingIndex = entry >> 24;
        if (encodingIndex < commonCount) encoding = Section32(info, infoSize, commonOffset + static_cast<unsigned long>(encodingIndex) * 4u, ok);
        else encoding = Section32(info, infoSize, pageOffset + encodingsOffset + static_cast<unsigned long>(encodingIndex - commonCount) * 4u, ok);
    } else return false;
    if (!ok || query.pc < funcStart || query.pc > funcEnd || funcEnd < funcStart) return false;
    Word lsda = 0;
    if (encoding & 0x40000000u) {
        if (lsdaEnd < lsdaOffset) return false;
        const auto count = (lsdaEnd - lsdaOffset) / 8u;
        const auto funcOff = static_cast<std::uint32_t>(funcStart - base);
        low = 0;
        high = count;
        while (low < high) {
            const auto mid = low + (high - low) / 2;
            const auto start = Section32(info, infoSize, lsdaOffset + static_cast<unsigned long>(mid) * 8u, ok);
            if (!ok) return false;
            if (start == funcOff) {
                lsda = base + Section32(info, infoSize, lsdaOffset + static_cast<unsigned long>(mid) * 8u + 4u, ok);
                break;
            }
            if (start < funcOff) low = mid + 1;
            else high = mid;
        }
        if (!ok || lsda == 0) return false;
    }
    Word personality = 0;
    const auto personalityIndex = (encoding >> 28) & 3u;
    if (personalityIndex != 0) {
        if (personalityIndex - 1 >= personalityCount) return false;
        const auto delta = static_cast<std::int32_t>(Section32(info, infoSize, personalityOffset + static_cast<unsigned long>(personalityIndex - 1) * 4u, ok));
        if (!ok) return false;
        const auto slot = static_cast<Word>(static_cast<std::intptr_t>(base) + delta);
        std::memcpy(&personality, reinterpret_cast<const void*>(slot), sizeof(personality));
    }
    if ((encoding & 0x0f000000u) == 0x04000000u) {
        unsigned long ehSize = 0;
        const auto* eh = getsectiondata(static_cast<const mach_header_64*>(image.dli_fbase), "__TEXT", "__eh_frame", &ehSize);
        const auto ehOffset = encoding & 0x00ffffffu;
        if (!eh || ehOffset >= ehSize) return false;
        query.fde = eh + ehOffset;
        query.text = base;
        query.data = base;
        frame = {};
        return DecodeCandidate(context, frame, query);
    }
    if ((encoding & 0x0f000000u) == 0) return false;
    frame = {};
    frame.useCompact = true;
    frame.compactEncoding = encoding;
    frame.functionStart = funcStart;
    frame.returnRegister = 16;
    context.region = funcStart;
    context.lsda = lsda;
    context.personality = personality;
    context.textBase = base;
    context.dataBase = base;
    return true;
}
#endif

bool DecodeFrame(_Unwind_Context& context, Frame& frame) {
    Lookup query {context.registers[16] - !context.signalFrame};
#if defined(__linux__) || defined(__APPLE__)
    dl_iterate_phdr(FindFrame, &query);
#ifdef __APPLE__
    if (!query.fde && AppleCompact(context, frame, query)) return true;
    if (!query.fde) {
        Dl_info image {};
        if (!dladdr(reinterpret_cast<void*>(query.pc), &image) || !image.dli_fbase) return false;
        unsigned long size = 0;
        const Byte* p = getsectiondata(static_cast<const mach_header_64*>(image.dli_fbase), "__TEXT", "__eh_frame", &size);
        if (!p) return false;
        const Byte* end = p + size;
        while (end - p >= 8) {
            const Byte* record = p;
            const auto length = Read<std::uint32_t>(p);
            if (length == 0) return false;
            if (length == 0xffffffff || length < 4 || Word(end - p) < length) return false;
            const Byte* next = p + length;
            if (Read<std::uint32_t>(p)) {
                query.fde = record;
                frame = {};
                if (DecodeCandidate(context, frame, query)) return true;
            }
            p = next;
        }
        return false;
    }
#endif
    return DecodeCandidate(context, frame, query);
#else
    void* image = nullptr;
    if (!RtlPcToFileHeader(reinterpret_cast<void*>(query.pc), &image) || !image) return false;
    const auto* base = static_cast<const Byte*>(image);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    const auto* sections = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const auto& section = sections[i];
        if (std::memcmp(section.Name, ".ehmeta", 8) == 0) {
            const Byte* metadata = base + section.VirtualAddress;
            const Byte* header = base + Read<std::uint32_t>(metadata);
            if (header[0] != 1 || header[3] == 255) return false;
            const Byte* p = header + 4;
            Encoded(p, header[1], Word(header));
            const Word count = Encoded(p, header[2]);
            const auto width = EncodingSize(header[3]);
            const Byte* table = p;
            Word lo = 0, hi = count;
            while (lo < hi) {
                const Word mid = lo + (hi - lo) / 2;
                p = table + mid * width * 2;
                if (Encoded(p, header[3], Word(header)) <= query.pc) lo = mid + 1;
                else hi = mid;
            }
            if (!lo) return false;
            p = table + (lo - 1) * width * 2 + width;
            query.fde = reinterpret_cast<const Byte*>(Encoded(p, header[3], Word(header)));
            return DecodeCandidate(context, frame, query);
        }
        if (std::memcmp(section.Name, ".ehfram", 8) != 0) continue;
        const Byte* frames = base + section.VirtualAddress;
        const ImageKey key {Word(base), nt->FileHeader.TimeDateStamp, nt->OptionalHeader.CheckSum, nt->OptionalHeader.SizeOfImage, section.VirtualAddress, section.Misc.VirtualSize};
        const auto& index = IndexFrames(key, frames, frames + section.Misc.VirtualSize);
        auto found = std::upper_bound(index.begin(), index.end(), query.pc, [](Word pc, const std::pair<Word, const Byte*>& entry) { return pc < entry.first; });
        if (found == index.begin()) continue;
        query.fde = std::prev(found)->second;
        frame = {};
        if (DecodeCandidate(context, frame, query)) return true;
    }
    return false;
#endif
}

struct Rule { unsigned kind {}; std::intptr_t value {}; const Byte* expression {}; };
#ifdef _WIN32
constexpr unsigned RuleCount = 33;
#else
constexpr unsigned RuleCount = 17;
#endif

struct Rules { Rule registers[RuleCount] {}; unsigned cfaRegister {7}; std::intptr_t cfaOffset {}; const Byte* cfaExpression {}; };

bool Instructions(const Byte* p, const Byte* end, const Frame& frame, Word target, Rules& state, const Rules& initial) {
    Word location = frame.start;
    Rules saved[16];
    unsigned depth = 0;
    while (p < end && location <= target) {
        Byte opcode = *p++;
        unsigned reg;
        if ((opcode & 192) == 64) { location += (opcode & 63) * frame.codeAlign; continue; }
        if ((opcode & 192) == 128) {
            reg = opcode & 63;
            auto offset = Uleb(p) * frame.dataAlign;
            if (reg < RuleCount) state.registers[reg] = {1, static_cast<std::intptr_t>(offset)};
            continue;
        }
        if ((opcode & 192) == 192) {
            reg = opcode & 63;
            if (reg < RuleCount) state.registers[reg] = initial.registers[reg];
            continue;
        }
        switch (opcode) {
        case 0: break;
        case 1: location = Read<Word>(p); break;
        case 2: location += Read<Byte>(p) * frame.codeAlign; break;
        case 3: location += Read<std::uint16_t>(p) * frame.codeAlign; break;
        case 4: location += Read<std::uint32_t>(p) * frame.codeAlign; break;
        case 5: case 17: case 20: case 21: {
            reg = Uleb(p);
            auto offset = (opcode == 17 || opcode == 21 ? Sleb(p) : std::intptr_t(Uleb(p))) * frame.dataAlign;
            if (reg < RuleCount) state.registers[reg] = {unsigned(opcode >= 20 ? 4 : 1), offset};
            break;
        }
        case 6: reg = Uleb(p); if (reg < RuleCount) state.registers[reg] = initial.registers[reg]; break;
        case 7: case 8: reg = Uleb(p); if (reg < RuleCount) state.registers[reg] = {unsigned(opcode == 7 ? 5 : 0)}; break;
        case 9: { reg = Uleb(p); auto other = Uleb(p); if (reg < RuleCount) state.registers[reg] = {2, std::intptr_t(other)}; break; }
        case 10: if (depth == 16) return false; saved[depth++] = state; break;
        case 11: if (!depth) return false; state = saved[--depth]; break;
        case 12: case 18:
            state.cfaExpression = nullptr; state.cfaRegister = Uleb(p);
            state.cfaOffset = opcode == 18 ? Sleb(p) * frame.dataAlign : Uleb(p); break;
        case 13: state.cfaRegister = Uleb(p); break;
        case 14: case 19: state.cfaOffset = opcode == 19 ? Sleb(p) * frame.dataAlign : Uleb(p); break;
        case 15: { state.cfaExpression = p; auto size = Uleb(p); p += size; break; }
        case 16: case 22: {
            reg = Uleb(p); const Byte* expr = p; auto size = Uleb(p); p += size;
            if (reg < RuleCount) state.registers[reg] = {unsigned(opcode == 16 ? 3 : 6), 0, expr};
            break;
        }
        case 46: Uleb(p); break;
        default: return false;
        }
    }
    return true;
}

bool Expression(const Byte* p, const _Unwind_Context& context, Word cfa, Word& result) {
    Word length = Uleb(p);
    const Byte* end = p + length;
    Word stack[64]; unsigned size = 0;
    unsigned steps = 0;
    while (p < end && ++steps < 4096) {
        Byte op = *p++;
        if (size >= 62) return false;
        if (op >= 48 && op <= 79) { stack[size++] = op - 48; continue; }
        if (op >= 80 && op <= 96) { stack[size++] = context.registers[op - 80]; continue; }
        if (op >= 112 && op <= 128) { stack[size++] = context.registers[op - 112] + Sleb(p); continue; }
        switch (op) {
        case 3: stack[size++] = Read<Word>(p); break;
        case 6: if (!size) return false; std::memcpy(&stack[size-1], reinterpret_cast<void*>(stack[size-1]), 8); break;
        case 8: stack[size++] = Read<Byte>(p); break;
        case 9: stack[size++] = Read<std::int8_t>(p); break;
        case 10: stack[size++] = Read<std::uint16_t>(p); break;
        case 11: stack[size++] = Read<std::int16_t>(p); break;
        case 12: stack[size++] = Read<std::uint32_t>(p); break;
        case 13: stack[size++] = Read<std::int32_t>(p); break;
        case 14: case 15: stack[size++] = Read<Word>(p); break;
        case 16: stack[size++] = Uleb(p); break;
        case 17: stack[size++] = Sleb(p); break;
        case 18: if (!size) return false; stack[size] = stack[size-1]; ++size; break;
        case 19: if (!size) return false; --size; break;
        case 20: if (size < 2) return false; stack[size] = stack[size-2]; ++size; break;
        case 22: if (size < 2) return false; { Word x=stack[size-1]; stack[size-1]=stack[size-2]; stack[size-2]=x; } break;
        case 26: case 28: case 30: case 33: case 34: case 36: case 37: case 39: case 41: case 42: case 43: case 44: case 45: case 46: {
            if (size < 2) return false;
            Word b = stack[--size], &a = stack[size-1];
            switch (op) {
            case 26: a &= b; break; case 28: a -= b; break; case 30: a *= b; break;
            case 33: a |= b; break; case 34: a += b; break; case 36: a = b < 64 ? a << b : 0; break;
            case 37: a = b < 64 ? a >> b : 0; break; case 39: a ^= b; break;
            case 41: a = a == b; break; case 42: a = std::intptr_t(a) >= std::intptr_t(b); break;
            case 43: a = std::intptr_t(a) > std::intptr_t(b); break; case 44: a = std::intptr_t(a) <= std::intptr_t(b); break;
            case 45: a = std::intptr_t(a) < std::intptr_t(b); break; case 46: a = a != b; break;
            }
            break;
        }
        case 35: if (!size) return false; stack[size-1] += Uleb(p); break;
        case 146: { auto reg = Uleb(p); if (reg >= 17) return false; stack[size++] = context.registers[reg] + Sleb(p); break; }
        case 150: break;
        case 156: stack[size++] = cfa; break;
        case 159: break;
        default: return false;
        }
    }
    if (p != end || size != 1) return false;
    result = stack[0]; return true;
}

bool CompactRules(Frame& frame, Rules& rules) {
    const auto encoding = frame.compactEncoding;
    const auto mode = encoding & 0x0f000000u;
    rules = {};
    frame.returnRegister = 16;
    auto save = [&](unsigned reg, std::intptr_t offset) {
        if (reg < RuleCount) rules.registers[reg] = {1, offset};
    };
    save(16, -8);
    if (mode == 0x01000000u) {
        rules.cfaRegister = 6;
        rules.cfaOffset = 16;
        save(6, -16);
        auto locations = encoding & 0x7fffu;
        const auto slot = static_cast<std::intptr_t>((encoding >> 16) & 0xffu);
        for (int index = 0; index < 5; ++index) {
            unsigned reg = 0;
            switch (locations & 7u) {
            case 1: reg = 3; break;
            case 2: reg = 12; break;
            case 3: reg = 13; break;
            case 4: reg = 14; break;
            case 5: reg = 15; break;
            case 0: break;
            default: return false;
            }
            if (reg) save(reg, -16 - 8 * slot + 8 * index);
            locations >>= 3;
        }
        return true;
    }
    if (mode != 0x02000000u && mode != 0x03000000u) return false;
    const auto stackEncoded = (encoding >> 16) & 0xffu;
    const auto stackAdjust = (encoding >> 13) & 7u;
    const auto regCount = (encoding >> 10) & 7u;
    auto permutation = encoding & 0x3ffu;
    if (regCount > 6) return false;
    std::uint32_t stackSize = stackEncoded * 8u;
    if (mode == 0x03000000u) {
        if (frame.functionStart == 0) return false;
        std::uint32_t immediate = 0;
        std::memcpy(&immediate, reinterpret_cast<const void*>(frame.functionStart + stackEncoded), 4);
        stackSize = immediate + 8u * stackAdjust;
    }
    if (stackSize > 0x10000000u) return false;
    rules.cfaRegister = 7;
    rules.cfaOffset = static_cast<std::intptr_t>(stackSize);
    unsigned permuted[6] = {};
    switch (regCount) {
    case 6:
        permuted[0] = permutation / 120; permutation -= permuted[0] * 120;
        permuted[1] = permutation / 24; permutation -= permuted[1] * 24;
        permuted[2] = permutation / 6; permutation -= permuted[2] * 6;
        permuted[3] = permutation / 2; permutation -= permuted[3] * 2;
        permuted[4] = permutation; permuted[5] = 0;
        break;
    case 5:
        permuted[0] = permutation / 120; permutation -= permuted[0] * 120;
        permuted[1] = permutation / 24; permutation -= permuted[1] * 24;
        permuted[2] = permutation / 6; permutation -= permuted[2] * 6;
        permuted[3] = permutation / 2; permutation -= permuted[3] * 2;
        permuted[4] = permutation;
        break;
    case 4:
        permuted[0] = permutation / 60; permutation -= permuted[0] * 60;
        permuted[1] = permutation / 12; permutation -= permuted[1] * 12;
        permuted[2] = permutation / 3; permutation -= permuted[2] * 3;
        permuted[3] = permutation;
        break;
    case 3:
        permuted[0] = permutation / 20; permutation -= permuted[0] * 20;
        permuted[1] = permutation / 4; permutation -= permuted[1] * 4;
        permuted[2] = permutation;
        break;
    case 2:
        permuted[0] = permutation / 5; permutation -= permuted[0] * 5;
        permuted[1] = permutation;
        break;
    case 1: permuted[0] = permutation; break;
    case 0: break;
    default: return false;
    }
    bool used[7] = {};
    static const unsigned dwarf[7] = {0, 3, 12, 13, 14, 15, 6};
    for (unsigned index = 0; index < regCount; ++index) {
        unsigned renumbered = 0;
        unsigned reg = 0;
        for (unsigned candidate = 1; candidate < 7; ++candidate) {
            if (used[candidate]) continue;
            if (renumbered == permuted[index]) { reg = dwarf[candidate]; used[candidate] = true; break; }
            ++renumbered;
        }
        if (reg == 0) return false;
        save(reg, -8 * static_cast<std::intptr_t>(regCount - index + 1));
    }
    return true;
}

bool GetRules(_Unwind_Context& context, Frame& frame, Rules& rules) {
    if (!DecodeFrame(context, frame)) return false;
    if (frame.useCompact) {
        if (!CompactRules(frame, rules)) return false;
        if (rules.cfaRegister >= 17) return false;
        context.cfa = context.registers[rules.cfaRegister] + rules.cfaOffset;
        return true;
    }
    Rules initial;
    if (!Instructions(frame.cieBegin, frame.cieEnd, frame, ~Word(0), initial, {})) return false;
#ifdef _WIN32
    if (frame.returnRegister == 32) {
        initial.registers[16] = initial.registers[32];
        initial.registers[32] = {};
        frame.returnRegister = 16;
    }
#endif
    rules = initial;
    if (!Instructions(frame.begin, frame.end, frame, context.registers[16] - !context.signalFrame, rules, initial)) return false;
    if (rules.cfaExpression) return Expression(rules.cfaExpression, context, 0, context.cfa);
    if (rules.cfaRegister >= 17) return false;
    context.cfa = context.registers[rules.cfaRegister] + rules.cfaOffset;
    return true;
}

bool Step(_Unwind_Context& context) {
    Frame frame; Rules rules;
    if (!GetRules(context, frame, rules)) return false;
    _Unwind_Context next = context;
    for (unsigned i = 0; i < 17; ++i) {
        const auto& rule = rules.registers[i];
        Word value;
        switch (rule.kind) {
        case 0: break;
        case 1: std::memcpy(&next.registers[i], reinterpret_cast<void*>(context.cfa + rule.value), 8); break;
        case 2: if (rule.value < 0 || rule.value >= 17) return false; next.registers[i] = context.registers[rule.value]; break;
        case 3: case 6:
            if (!Expression(rule.expression, context, context.cfa, value)) return false;
            if (rule.kind == 3) std::memcpy(&value, reinterpret_cast<void*>(value), 8);
            next.registers[i] = value; break;
        case 4: next.registers[i] = context.cfa + rule.value; break;
        case 5: next.registers[i] = 0; break;
        }
    }
#ifdef _WIN32
    for (unsigned i = 17; i < RuleCount; ++i) {
        const auto& rule = rules.registers[i];
        auto* destination = next.vectorRegisters[i - 17];
        if (rule.kind == 1) std::memcpy(destination, reinterpret_cast<void*>(context.cfa + rule.value), 16);
        else if (rule.kind == 2 && rule.value >= 17 && rule.value < RuleCount)
            std::memcpy(destination, context.vectorRegisters[rule.value - 17], 16);
        else if (rule.kind == 3) {
            Word address;
            if (!Expression(rule.expression, context, context.cfa, address)) return false;
            std::memcpy(destination, reinterpret_cast<const void*>(address), 16);
        }
        else if (rule.kind == 5) std::memset(destination, 0, 16);
        else if (rule.kind != 0) return false;
    }
#endif
    next.registers[7] = context.cfa;
    next.registers[16] = next.registers[frame.returnRegister];
    next.signalFrame = frame.signal;
    if (!next.registers[16] || (next.registers[7] == context.registers[7] && next.registers[16] == context.registers[16])) return false;
    context = next;
    return true;
}

_Unwind_Reason_Code PhaseTwo(_Unwind_Context context, _Unwind_Exception* exception) {
    for (unsigned depth = 0; depth < 65536; ++depth) {
        Frame frame; Rules rules;
        if (!GetRules(context, frame, rules)) {
            if (exception->private_1) {
                auto stop = reinterpret_cast<_Unwind_Stop_Fn>(exception->private_1);
                return stop(1, _Unwind_Action(_UA_FORCE_UNWIND | _UA_CLEANUP_PHASE | _UA_END_OF_STACK), exception->exception_class, exception, &context, reinterpret_cast<void*>(exception->private_2));
            }
            return _URC_END_OF_STACK;
        }
        {
            auto actions = _UA_CLEANUP_PHASE;
            if (exception->private_1) {
                actions = _Unwind_Action(actions | _UA_FORCE_UNWIND);
                auto stop = reinterpret_cast<_Unwind_Stop_Fn>(exception->private_1);
                auto result = stop(1, actions, exception->exception_class, exception, &context, reinterpret_cast<void*>(exception->private_2));
                if (result != _URC_NO_REASON) return result;
            } else if (context.cfa == exception->private_2) actions = _Unwind_Action(actions | _UA_HANDLER_FRAME);
            if (frame.personality) {
                auto result = CallPersonality(frame.personality, actions, exception, &context);
                if (result == _URC_INSTALL_CONTEXT) LibcRestoreRegisters(context.registers);
                if (result != _URC_CONTINUE_UNWIND) return _URC_FATAL_PHASE2_ERROR;
            }
        }
        if (!Step(context)) {
            if (exception->private_1) {
                auto stop = reinterpret_cast<_Unwind_Stop_Fn>(exception->private_1);
                return stop(1, _Unwind_Action(_UA_FORCE_UNWIND | _UA_CLEANUP_PHASE | _UA_END_OF_STACK), exception->exception_class, exception, &context, reinterpret_cast<void*>(exception->private_2));
            }
            return _URC_FATAL_PHASE2_ERROR;
        }
    }
    return _URC_FATAL_PHASE2_ERROR;
}
}

extern "C" {
_Unwind_Reason_Code APS5_VABI _Unwind_RaiseException_nid_postfix(_Unwind_Exception* exception) {
    _Unwind_Context start;
    LibcCaptureRegisters(start.registers);
    if (!LibcUnwind::Step(start)) return _URC_FATAL_PHASE1_ERROR;
    auto context = start;
    exception->private_1 = 0;
    for (unsigned depth = 0; depth < 65536; ++depth) {
        LibcUnwind::Frame frame; LibcUnwind::Rules rules;
        if (!LibcUnwind::GetRules(context, frame, rules)) return _URC_END_OF_STACK;
        if (frame.personality) {
            auto result = LibcUnwind::CallPersonality(frame.personality, _UA_SEARCH_PHASE, exception, &context);
            if (result == _URC_HANDLER_FOUND) {
                exception->private_2 = context.cfa;
                return LibcUnwind::PhaseTwo(start, exception);
            }
            if (result != _URC_CONTINUE_UNWIND) return _URC_FATAL_PHASE1_ERROR;
        }
        if (!LibcUnwind::Step(context)) return _URC_END_OF_STACK;
    }
    return _URC_FATAL_PHASE1_ERROR;
}

[[noreturn]] void APS5_VABI _Unwind_Resume_nid_postfix(_Unwind_Exception* exception) {
#if defined(__linux__)
    if (!LibcException::Native(exception->exception_class) && !exception->private_1) {
        using Resume = void (*)(_Unwind_Exception*);
        const auto resume = reinterpret_cast<Resume>(dlsym(RTLD_NEXT, "_Unwind_Resume"));
        if (!resume) std::abort();
        resume(exception);
    }
#endif
    _Unwind_Context context;
    LibcCaptureRegisters(context.registers);
    if (!LibcUnwind::Step(context)) std::abort();
    LibcUnwind::PhaseTwo(context, exception);
    std::abort();
}

_Unwind_Reason_Code APS5_VABI _Unwind_Resume_or_Rethrow_nid_postfix(_Unwind_Exception* exception) {
    if (exception->private_1) _Unwind_Resume_nid_postfix(exception);
    return _Unwind_RaiseException_nid_postfix(exception);
}

void APS5_VABI _Unwind_DeleteException_nid_postfix(_Unwind_Exception* exception) {
    if (exception && exception->exception_cleanup) exception->exception_cleanup(_URC_FOREIGN_EXCEPTION_CAUGHT, exception);
}

_Unwind_Word APS5_VABI _Unwind_GetGR_nid_postfix(_Unwind_Context* context, int index) {
    if (index < 0 || index >= 17) std::abort();
    return context->registers[index];
}
void APS5_VABI _Unwind_SetGR_nid_postfix(_Unwind_Context* context, int index, _Unwind_Word value) {
    if (index < 0 || index >= 17) std::abort();
    context->registers[index] = value;
}
_Unwind_Ptr APS5_VABI _Unwind_GetIP_nid_postfix(_Unwind_Context* context) { return context->registers[16]; }
void APS5_VABI _Unwind_SetIP_nid_postfix(_Unwind_Context* context, _Unwind_Ptr value) { context->registers[16] = value; }
_Unwind_Ptr APS5_VABI _Unwind_GetIPInfo_nid_postfix(_Unwind_Context* context, int* before) { if (before) *before = context->signalFrame; return context->registers[16]; }
_Unwind_Word APS5_VABI _Unwind_GetCFA_nid_postfix(_Unwind_Context* context) { return context->cfa; }
_Unwind_Ptr APS5_VABI _Unwind_GetLanguageSpecificData_nid_postfix(_Unwind_Context* context) { return context->lsda; }
_Unwind_Ptr APS5_VABI _Unwind_GetRegionStart_nid_postfix(_Unwind_Context* context) { return context->region; }
_Unwind_Ptr APS5_VABI _Unwind_GetDataRelBase_nid_postfix(_Unwind_Context* context) { return context->dataBase; }
_Unwind_Ptr APS5_VABI _Unwind_GetTextRelBase_nid_postfix(_Unwind_Context* context) { return context->textBase; }

_Unwind_Reason_Code APS5_VABI _Unwind_ForcedUnwind_nid_postfix(_Unwind_Exception* exception, _Unwind_Stop_Fn stop, void* argument) {
    if (!stop) return _URC_FATAL_PHASE2_ERROR;
    _Unwind_Context context;
    LibcCaptureRegisters(context.registers);
    if (!LibcUnwind::Step(context)) return _URC_FATAL_PHASE2_ERROR;
    exception->private_1 = reinterpret_cast<std::uintptr_t>(stop);
    exception->private_2 = reinterpret_cast<std::uintptr_t>(argument);
    return LibcUnwind::PhaseTwo(context, exception);
}

_Unwind_Reason_Code APS5_VABI _Unwind_Backtrace_nid_postfix(_Unwind_Trace_Fn trace, void* argument) {
    _Unwind_Context context;
    LibcCaptureRegisters(context.registers);
    if (!LibcUnwind::Step(context)) return _URC_END_OF_STACK;
    for (unsigned depth = 0; depth < 65536; ++depth) {
        LibcUnwind::Frame frame; LibcUnwind::Rules rules;
        if (!LibcUnwind::GetRules(context, frame, rules)) return _URC_END_OF_STACK;
        auto result = trace(&context, argument);
        if (result != _URC_NO_REASON) return result;
        if (!LibcUnwind::Step(context)) return _URC_END_OF_STACK;
    }
    return _URC_FATAL_PHASE1_ERROR;
}
}

#else

extern "C" {
_Unwind_Reason_Code APS5_VABI _Unwind_RaiseException_nid_postfix(_Unwind_Exception*) { std::abort(); }
[[noreturn]] void APS5_VABI _Unwind_Resume_nid_postfix(_Unwind_Exception*) { std::abort(); }
_Unwind_Reason_Code APS5_VABI _Unwind_Resume_or_Rethrow_nid_postfix(_Unwind_Exception*) { std::abort(); }
void APS5_VABI _Unwind_DeleteException_nid_postfix(_Unwind_Exception* e) { if (e && e->exception_cleanup) e->exception_cleanup(_URC_FOREIGN_EXCEPTION_CAUGHT, e); }
_Unwind_Word APS5_VABI _Unwind_GetGR_nid_postfix(_Unwind_Context*, int) { std::abort(); }
void APS5_VABI _Unwind_SetGR_nid_postfix(_Unwind_Context*, int, _Unwind_Word) { std::abort(); }
_Unwind_Ptr APS5_VABI _Unwind_GetIP_nid_postfix(_Unwind_Context*) { std::abort(); }
void APS5_VABI _Unwind_SetIP_nid_postfix(_Unwind_Context*, _Unwind_Ptr) { std::abort(); }
_Unwind_Ptr APS5_VABI _Unwind_GetIPInfo_nid_postfix(_Unwind_Context*, int*) { std::abort(); }
_Unwind_Word APS5_VABI _Unwind_GetCFA_nid_postfix(_Unwind_Context*) { std::abort(); }
_Unwind_Ptr APS5_VABI _Unwind_GetLanguageSpecificData_nid_postfix(_Unwind_Context*) { std::abort(); }
_Unwind_Ptr APS5_VABI _Unwind_GetRegionStart_nid_postfix(_Unwind_Context*) { std::abort(); }
_Unwind_Ptr APS5_VABI _Unwind_GetDataRelBase_nid_postfix(_Unwind_Context*) { std::abort(); }
_Unwind_Ptr APS5_VABI _Unwind_GetTextRelBase_nid_postfix(_Unwind_Context*) { std::abort(); }
_Unwind_Reason_Code APS5_VABI _Unwind_ForcedUnwind_nid_postfix(_Unwind_Exception*, _Unwind_Stop_Fn, void*) { std::abort(); }
_Unwind_Reason_Code APS5_VABI _Unwind_Backtrace_nid_postfix(_Unwind_Trace_Fn, void*) { std::abort(); }
}

#endif
