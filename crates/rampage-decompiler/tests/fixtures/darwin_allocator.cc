// Compile with -std=c++14, the vendor include path, librampage_ghidra.a and -lz; pass the specs directory.
#include "../../src/shim.cc"

#include <cassert>
#include <cstdio>

namespace {
std::vector<ParameterPieces> allocate(ProtoModel &model, TypeFactory &types,
    const std::vector<Datatype *> &inputs, int4 firstVarArg = -1, Datatype *output = nullptr) {
    PrototypePieces prototype;
    prototype.model = &model;
    prototype.name = "allocation";
    prototype.outtype = output == nullptr ? types.getTypeVoid() : output;
    prototype.intypes = inputs;
    prototype.firstVarArgSlot = firstVarArg;
    std::vector<ParameterPieces> result;
    model.assignParameterStorage(prototype, result, false);
    return result;
}

void stack(const ParameterPieces &piece, uintb offset, int4 size, bool indirect = false) {
    assert(!piece.addr.isInvalid());
    assert(piece.addr.getSpace()->getName() == "stack");
    if (piece.addr.getOffset() != offset)
        fprintf(stderr, "Stack offset: expected %llu, got %llu (size %d)\n",
            (unsigned long long)offset, (unsigned long long)piece.addr.getOffset(), size);
    assert(piece.addr.getOffset() == offset);
    assert(piece.type->getSize() == size);
    assert(((piece.flags & ParameterPieces::indirectstorage) != 0) == indirect);
}

void reg(Architecture &arch, const ParameterPieces &piece, const char *name) {
    const VarnodeData &expected = arch.translate->getRegister(name);
    assert(piece.addr == expected.getAddr());
}

void joined(Architecture &arch, const ParameterPieces &piece, const std::vector<std::string> &names) {
    assert(piece.addr.getSpace()->getType() == IPTR_JOIN);
    const JoinRecord *record = arch.findJoin(piece.addr.getOffset());
    assert(record->numPieces() == names.size());
    for (int4 index = 0; index < record->numPieces(); ++index) {
        const VarnodeData &expected = arch.translate->getRegister(names[index]);
        assert(record->getPiece(index).getAddr() == expected.getAddr());
    }
}

void testModel(Architecture &arch, ProtoModel &model) {
    TypeFactory &types = *arch.types;
    Datatype *byte = types.getBase(1, TYPE_INT);
    Datatype *half = types.getBase(2, TYPE_INT);
    Datatype *word = types.getBase(4, TYPE_INT);
    Datatype *wide = types.getBase(8, TYPE_INT);
    Datatype *quad = types.getBase(16, TYPE_INT, "darwin_int128");
    assert(quad->getAlignment() == 16);
    Datatype *floating = types.getBase(8, TYPE_FLOAT);
    PrototypePieces composites;
    std::istringstream declaration(
        "void composites(Hfa3 large_hfa, HfaFloat3 small_hfa, Big aggregate, BigUnion u, Small small, SmallUnion su);");
    parse_protopieces(composites, declaration, &arch);
    Datatype *hfa = composites.intypes[0];
    Datatype *smallHfa = composites.intypes[1];
    Datatype *big = composites.intypes[2];
    Datatype *bigUnion = composites.intypes[3];
    Datatype *small = composites.intypes[4];
    Datatype *smallUnion = composites.intypes[5];

    std::vector<Datatype *> fixed(8, wide);
    fixed.insert(fixed.end(), {byte, half, byte, word});
    auto result = allocate(model, types, fixed);
    assert(result.size() == 13);
    stack(result[9], 0, 1);
    stack(result[10], 2, 2);
    stack(result[11], 4, 1);
    stack(result[12], 8, 4);

    fixed.assign(8, wide);
    fixed.insert(fixed.end(), {byte, small, byte});
    result = allocate(model, types, fixed);
    stack(result[9], 0, 1);
    stack(result[10], 8, 3);
    stack(result[11], 16, 1);
    fixed[9] = smallUnion;
    result = allocate(model, types, fixed);
    stack(result[9], 0, 1);
    stack(result[10], 8, 3);
    stack(result[11], 16, 1);

    result = allocate(model, types, {small, wide});
    reg(arch, result[1], "x0");
    reg(arch, result[2], "x1");

    fixed.assign(7, wide);
    fixed.insert(fixed.end(), {small, byte});
    result = allocate(model, types, fixed);
    reg(arch, result[8], "x7");
    stack(result[9], 0, 1);

    fixed.assign(8, wide);
    fixed.insert(fixed.end(), {byte, types.getTypeArray(3, byte), byte});
    result = allocate(model, types, fixed);
    stack(result[9], 0, 1);
    stack(result[10], 8, 3);
    stack(result[11], 16, 1);

    fixed.assign(7, wide);
    fixed.insert(fixed.end(), {quad, wide});
    result = allocate(model, types, fixed);
    assert(result.size() == 10);
    for (int4 index = 0; index < 7; ++index)
        reg(arch, result[index + 1], ("x" + std::to_string(index)).c_str());
    stack(result[8], 0, 16);
    stack(result[9], 16, 8);

    fixed.assign(6, wide);
    fixed.insert(fixed.end(), {quad, wide});
    result = allocate(model, types, fixed);
    joined(arch, result[7], {"x7", "x6"});
    stack(result[8], 0, 8);

    PrototypePieces pairPrototype;
    std::istringstream pairDeclaration("void pair(Pair value);");
    parse_protopieces(pairPrototype, pairDeclaration, &arch);
    fixed.assign(7, wide);
    fixed.insert(fixed.end(), {pairPrototype.intypes[0], wide});
    result = allocate(model, types, fixed);
    stack(result[8], 0, 16);
    stack(result[9], 16, 8);

    fixed.assign(7, wide);
    fixed.insert(fixed.end(), {types.getTypeArray(12, byte), wide});
    result = allocate(model, types, fixed);
    stack(result[8], 0, 12);
    stack(result[9], 16, 8);

    result = allocate(model, types, {word, quad, wide});
    reg(arch, result[1], "x0");
    joined(arch, result[2], {"x2", "x1"});
    reg(arch, result[3], "x3");

    result = allocate(model, types, {word, floating, byte, half, quad, floating,
        hfa, big, bigUnion, smallHfa, byte}, 2);
    assert(result.size() == 12);
    reg(arch, result[1], "x0");
    reg(arch, result[2], "d0");
    stack(result[3], 0, 1);
    stack(result[4], 8, 2);
    stack(result[5], 16, 16);
    stack(result[6], 32, 8);
    stack(result[7], 40, 24);
    stack(result[8], 64, 8, true);
    stack(result[9], 72, 8, true);
    stack(result[10], 80, 12);
    stack(result[11], 96, 1);
    assert(static_cast<TypePointer *>(result[8].type)->getPtrTo() == big);
    assert(static_cast<TypePointer *>(result[9].type)->getPtrTo() == bigUnion);

    result = allocate(model, types, {hfa, word, floating}, 2);
    joined(arch, result[1], {"d2", "d1", "d0"});
    reg(arch, result[2], "x0");
    stack(result[3], 0, 8);

    fixed.assign(8, wide);
    fixed.insert(fixed.end(), {byte, byte, byte, quad});
    result = allocate(model, types, fixed, 9);
    stack(result[9], 0, 1);
    stack(result[10], 8, 1);
    stack(result[11], 16, 1);
    stack(result[12], 32, 16);

    std::vector<Datatype *> many = {word, floating};
    many.insert(many.end(), 100, wide);
    result = allocate(model, types, many, 2);
    assert(result.size() == 103);
    reg(arch, result[1], "x0");
    reg(arch, result[2], "d0");
    for (int4 index = 0; index < 100; ++index)
        stack(result[index + 3], index * 8, 8);
    for (int4 index = 0; index < 100; ++index)
        many[index + 2] = (index % 2 == 0) ? floating : wide;
    result = allocate(model, types, many, 2);
    assert(result.size() == 103);
    for (int4 index = 0; index < 100; ++index)
        stack(result[index + 3], index * 8, 8);

    Datatype *halfRange = types.getTypeArray(524288, byte);
    result = allocate(model, types, {halfRange, halfRange}, 0);
    stack(result[1], 0, 524288);
    stack(result[2], 524288, 524288);
    for (const std::vector<Datatype *> &inputs : {
        std::vector<Datatype *>{halfRange, halfRange, byte},
        std::vector<Datatype *>{byte, types.getTypeArray(1048576, byte)}}) {
        bool rejected = false;
        try {
            allocate(model, types, inputs, 0);
        } catch (const LowlevelError &error) {
            rejected = error.explain.find("exceeds the stack parameter range") != std::string::npos;
        }
        assert(rejected);
    }

    result = allocate(model, types, {hfa, floating, big, word});
    joined(arch, result[1], {"d2", "d1", "d0"});
    reg(arch, result[2], "d3");
    reg(arch, result[3], "x0");
    assert((result[3].flags & ParameterPieces::indirectstorage) != 0);
    reg(arch, result[4], "x1");

    result = allocate(model, types, {}, -1, hfa);
    assert(result.size() == 1);
    joined(arch, result[0], {"d2", "d1", "d0"});
    result = allocate(model, types, {}, -1, floating);
    assert(result.size() == 1);
    reg(arch, result[0], "d0");

    fixed.assign(8, wide);
    fixed.insert(fixed.end(), 8, floating);
    fixed.insert(fixed.end(), {smallHfa, byte});
    result = allocate(model, types, fixed);
    stack(result[17], 0, 12);
    stack(result[18], 12, 1);

    fixed.assign(8, wide);
    fixed.insert(fixed.end(), 8, floating);
    fixed.insert(fixed.end(), {byte, smallHfa, byte});
    result = allocate(model, types, fixed);
    stack(result[17], 0, 1);
    stack(result[18], 4, 12);
    stack(result[19], 16, 1);

    result = allocate(model, types, {word}, -1, big);
    assert(result.size() == 3);
    reg(arch, result[1], "x8");
    assert((result[1].flags & ParameterPieces::hiddenretparm) != 0);
    reg(arch, result[2], "x0");

    const VarnodeData &x18 = arch.translate->getRegister("x18");
    assert(model.hasEffect(x18.getAddr(), x18.size) == EffectRecord::unaffected);
}
}

int main(int argc, char **argv) try {
    assert(argc == 2);
    const uint8_t code[] = {0xc0, 0x03, 0x5f, 0xd6};
    const uint64_t bases[] = {0x1000};
    const uint8_t *bytes[] = {code};
    const size_t lengths[] = {sizeof(code)};
    const uint64_t sizes[] = {sizeof(code)};
    const uint8_t readable[] = {1}, executable[] = {1}, writable[] = {0};
    Handle *handle = static_cast<Handle *>(rampage_decomp_open(argv[1], "AARCH64:LE:64:v8A:apple", 1,
        bases, bytes, lengths, sizes, readable, executable, writable));
    assert(handle != nullptr && rampage_decomp_error(handle) == nullptr);
    for (const char *definition : {
        "struct Hfa3 { float8 a; float8 b; float8 c; };",
        "struct HfaFloat3 { float4 a; float4 b; float4 c; };",
        "struct Big { int8 a; int8 b; int4 c; };",
        "union BigUnion { Big a; int8 b; };",
        "struct Small { int1 a; int1 b; int1 c; };",
        "union SmallUnion { Small a; int1 b; };",
        "struct Pair { int8 a; int8 b; };"}) {
        const char *error = rampage_decomp_parse_c(handle, definition);
        if (error != nullptr) fprintf(stderr, "%s\n", error);
        assert(error == nullptr);
    }
    testModel(*handle->arch, *handle->arch->defaultfp);
    {
        ProtoModel cloned("apple_clone", *handle->arch->defaultfp);
        testModel(*handle->arch, cloned);
    }
    rampage_decomp_close(handle);
    handle = static_cast<Handle *>(rampage_decomp_open(argv[1], "AARCH64:LE:64:v8A:default", 1,
        bases, bytes, lengths, sizes, readable, executable, writable));
    assert(handle != nullptr && rampage_decomp_error(handle) == nullptr);
    assert(rampage_decomp_parse_c(handle, "struct HfaFloat3 { float4 a; float4 b; float4 c; };") == nullptr);
    TypeFactory &types = *handle->arch->types;
    Datatype *wide = types.getBase(8, TYPE_INT);
    Datatype *floating = types.getBase(8, TYPE_FLOAT);
    Datatype *byte = types.getBase(1, TYPE_INT);
    PrototypePieces composite;
    std::istringstream declaration("void aggregate(HfaFloat3 a);");
    parse_protopieces(composite, declaration, handle->arch);
    std::vector<Datatype *> fixed(8, wide);
    fixed.insert(fixed.end(), 8, floating);
    fixed.insert(fixed.end(), {composite.intypes[0], byte});
    auto result = allocate(*handle->arch->defaultfp, types, fixed);
    stack(result[17], 0, 12);
    stack(result[18], 16, 1);
    rampage_decomp_close(handle);
    puts("Darwin allocator passed (original and cloned model)");
} catch (const LowlevelError &error) {
    fprintf(stderr, "%s\n", error.explain.c_str());
    return 1;
}
