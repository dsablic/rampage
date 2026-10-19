// Owned native regression fixture for the adapted Ghidra parser, runnable with ASan/UBSan.
#include "context.hh"
#include "translate.hh"

#include <cassert>
#include <cstdint>
#include <limits>

using namespace ghidra;

template<typename Read> void rejects(Read read) {
    bool rejected = false;
    try { read(); } catch (const BadDataError &) { rejected = true; }
    assert(rejected);
}

int main() {
    ParserContext parser(nullptr, nullptr);
    uint8_t reference[20]{};
    for (uint4 i = 0; i < 16; ++i) {
        reference[i] = uint8_t(i + 1);
        parser.getBuffer()[i] = reference[i];
    }
    for (uint4 offset = 0; offset < 16; ++offset) {
        for (int4 size = 1; size <= 4; ++size) {
            uintm expected = 0;
            for (int4 i = 0; i < size; ++i) expected = expected * 256 + reference[offset + i];
            assert(parser.getInstructionBytes(0, size, offset) == expected);
            assert(parser.getInstructionBytes(int4(offset), size, 0) == expected);
        }
        for (int4 start = 0; start < 8; ++start) {
            for (int4 size = 1; size <= 32; ++size) {
                int4 bytes = (start + size + 7) / 8;
                uint64_t wide = 0;
                for (int4 i = 0; i < bytes; ++i) wide = wide * 256 + reference[offset + i];
                uint64_t mask = (uint64_t(1) << size) - 1;
                uintm expected = uintm((wide >> (bytes * 8 - start - size)) & mask);
                assert(parser.getInstructionBits(start, size, offset) == expected);
                assert(parser.getInstructionBits(int4(offset * 8) + start, size, 0) == expected);
            }
        }
    }
    assert(parser.getInstructionBytes(0, 4, 13) == 0x0e0f1000);
    assert(parser.getInstructionBits(1, 32, 13) == 0x1c1e2000);
    for (uint4 offset : {uint4(0), uint4(15), std::numeric_limits<uint4>::max()}) {
        rejects([&] { parser.getInstructionBytes(-1, 1, offset); });
        rejects([&] { parser.getInstructionBytes(0, -1, offset); });
        rejects([&] { parser.getInstructionBytes(0, 0, offset); });
        rejects([&] { parser.getInstructionBytes(0, 5, offset); });
        rejects([&] { parser.getInstructionBits(-1, 1, offset); });
        rejects([&] { parser.getInstructionBits(0, -1, offset); });
        rejects([&] { parser.getInstructionBits(0, 0, offset); });
        rejects([&] { parser.getInstructionBits(0, 33, offset); });
    }
    rejects([&] { parser.getInstructionBytes(0, 1, 16); });
    rejects([&] { parser.getInstructionBits(0, 1, 16); });
    rejects([&] { parser.getInstructionBits(128, 1, 0); });
    rejects([&] { parser.getInstructionBytes(std::numeric_limits<int4>::max(), 1,
                                           std::numeric_limits<uint4>::max()); });
    rejects([&] { parser.getInstructionBits(std::numeric_limits<int4>::max(), 1,
                                          std::numeric_limits<uint4>::max()); });
    return 0;
}
