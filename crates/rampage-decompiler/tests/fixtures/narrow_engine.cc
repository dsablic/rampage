#include "../../src/shim.cc"
#include "coreaction.hh"

#include <cassert>
#include <cstdio>
#include <memory>

namespace {
struct CallerInstruction {
    uint32_t word;
    const char *assembly;
};

const CallerInstruction callerInstructions[] = {
    {0xa9bf7bfdu, "stpx29,x30,[sp,#-16]!"},
    {0x910003fdu, "movx29,sp"},
    {0x13001c00u, "sxtbw0,w0"},
    {0x13003c21u, "sxthw1,w1"},
    {0x940003fcu, "bl_narrow_return_char"},
    {0x13001c00u, "sxtbw0,w0"},
    {0xa8c17bfdu, "ldpx29,x30,[sp],#16"},
    {0xd65f03c0u, "ret"},
};

class OwnedEndianSpaces : public AddrSpaceManager {
public:
    OwnedEndianSpaces() {
        insertSpace(new ConstantSpace(this, nullptr));
        insertSpace(new AddrSpace(this, nullptr, IPTR_PROCESSOR, "be_actual", true, 4, 1, 1, 0, 0, 0));
        AddrSpace *reverse = new AddrSpace(this, nullptr, IPTR_PROCESSOR, "be_reverse", true, 4, 1, 2, 0, 0, 0);
        insertSpace(reverse);
        setReverseJustified(reverse);
        setDefaultCodeSpace(1);
        setDefaultDataSpace(1);
    }
};

struct CloseHandle {
    void operator()(Handle *handle) const { rampage_decomp_close(handle); }
};
using OwnedHandle = std::unique_ptr<Handle, CloseHandle>;

OwnedHandle open(const char *specs, const char *language,
    const std::vector<uint8_t> &code = {0xc0, 0x03, 0x5f, 0xd6}) {
    const uint64_t bases[] = {0x1000}, sizes[] = {code.size()};
    const uint8_t *bytes[] = {code.data()};
    const size_t lengths[] = {code.size()};
    const uint8_t readable[] = {1}, writable[] = {0}, executable[] = {1};
    OwnedHandle handle(static_cast<Handle *>(rampage_decomp_open(specs, language, 1,
        bases, bytes, lengths, sizes, readable, executable, writable)));
    assert(handle != nullptr && rampage_decomp_error(handle.get()) == nullptr);
    return handle;
}

Funcdata *prepare(Handle &handle, const char *prototype) {
    Address address(handle.arch->getDefaultCodeSpace(), 0x1000);
    Funcdata *function = handle.arch->symboltab->getGlobalScope()->addFunction(address, "gate")->getFunction();
    PrototypePieces pieces;
    std::istringstream declaration(prototype);
    parse_protopieces(pieces, declaration, handle.arch);
    function->getFuncProto().setPieces(pieces);
    return function;
}

void queryModel(Architecture &arch, ProtoModel &model, bool apple) {
    for (int index = 0; index < 8; ++index) {
        const VarnodeData &reg = arch.translate->getRegister("x" + std::to_string(index));
        for (int4 size : {1, 2, 4, 8}) {
            VarnodeData result;
            OpCode opcode = model.assumedInputExtension(reg.getAddr(), size, result);
            if (size == 8 || (apple && size == 4)) {
                assert(opcode == CPUI_COPY);
            } else {
                assert(opcode == (apple ? CPUI_PIECE : CPUI_INT_ZEXT));
                assert(result.getAddr() == reg.getAddr());
                assert(result.size == (apple ? 4 : 8));
            }
        }
        VarnodeData result;
        assert(model.assumedInputExtension(reg.getAddr() + 1, 1, result) == CPUI_COPY);
    }
    const VarnodeData &x0 = arch.translate->getRegister("x0");
    for (int4 size : {1, 2, 4}) {
        VarnodeData result;
        assert(model.assumedOutputExtension(x0.getAddr(), size, result) == CPUI_INT_ZEXT);
        assert(result.size == 8 && result.getAddr() == x0.getAddr());
    }
    VarnodeData result;
    assert(model.assumedInputExtension(Address(arch.getStackSpace(), 0), 1, result) == CPUI_COPY);
    assert(model.assumedInputExtension(Address(arch.getStackSpace(), 2), 2, result) == CPUI_COPY);
}

void checkLockedInputs(Handle &handle, bool apple) {
    Funcdata *function = prepare(handle,
        "uint8 gate(int1 a, uint1 b, int2 c, uint2 d, int4 word, uint8 wide);");
    function->followFlow(function->getAddress(),
        Address(handle.arch->getDefaultCodeSpace(), handle.arch->getDefaultCodeSpace()->getHighest()));
    ActionPrototypeTypes action("base");
    action.apply(*function);
    int signExtensions = 0, zeroExtensions = 0;
    for (OpCode opcode : {CPUI_INT_SEXT, CPUI_INT_ZEXT}) {
        for (auto iter = function->beginOpAlive(); iter != function->endOpAlive(); ++iter) {
            PcodeOp *op = *iter;
            if (op->isDead() || op->code() != opcode) continue;
            assert(op->getOut()->getSize() == (apple ? 4 : 8));
            int parameter = -1;
            for (int index = 0; index < 6; ++index) {
                if (op->getIn(0)->getAddr() == function->getFuncProto().getParam(index)->getAddress())
                    parameter = index;
            }
            assert(parameter >= 0 && parameter < (apple ? 4 : 5));
            assert(opcode == (apple && (parameter == 0 || parameter == 2) ? CPUI_INT_SEXT : CPUI_INT_ZEXT));
            if (opcode == CPUI_INT_SEXT) ++signExtensions;
            else ++zeroExtensions;
        }
    }
    assert(signExtensions == (apple ? 2 : 0));
    assert(zeroExtensions == (apple ? 2 : 5));
}

void checkUnknownUpperBits(Handle &handle) {
    Funcdata *function = prepare(handle, "uint8 gate(int1 value);");
    char *code = rampage_decomp_function(&handle, 0x1000, "gate", 0);
    if (code == nullptr) fprintf(stderr, "%s\n", rampage_decomp_error(&handle));
    assert(code != nullptr);
    printf("Full-X read with a narrow input (upper 32 bits are not guaranteed):\n%s\n", code);
    free(code);
    const VarnodeData &x0 = handle.arch->translate->getRegister("x0");
    Address upper = x0.getAddr() + 4;
    bool unknownUpper = false;
    for (auto iter = function->beginDef(Varnode::input); iter != function->endDef(Varnode::input); ++iter) {
        Varnode *input = *iter;
        if (input->isLockedInput() || input->getSpace() != upper.getSpace()) continue;
        uintb begin = input->getOffset();
        if (begin > upper.getOffset()) continue;
        uintb relative = upper.getOffset() - begin;
        if (relative <= (uintb)input->getSize() && (uintb)input->getSize() - relative >= 4)
            unknownUpper = true;
    }
    assert(unknownUpper);
}

void checkCallSide(Handle &handle) {
    Funcdata *function = prepare(handle, "int4 gate(int4 first, int4 second);");
    function->followFlow(function->getAddress(),
        Address(handle.arch->getDefaultCodeSpace(), handle.arch->getDefaultCodeSpace()->getHighest()));
    assert(function->numCalls() == 1);
    FuncCallSpecs *call = function->getCallSpecs(0);
    assert(call->getEntryAddress() == Address(handle.arch->getDefaultCodeSpace(), 0x2000));
    call->setInternal(handle.arch->defaultfp, handle.arch->types->getTypeVoid());
    PrototypePieces pieces;
    std::istringstream declaration("uint1 narrow_return_char(int1 first, int2 second);");
    parse_protopieces(pieces, declaration, handle.arch);
    call->setPieces(pieces);
    ActionFuncLink action("base");
    action.apply(*function);
    PcodeOp *op = call->getOp();
    assert(op->numInput() == 4);
    assert(op->getIn(1)->getSize() == 1 && op->getIn(2)->getSize() == 2);
    assert(op->getIn(3)->isSpacebasePlaceholder());
    assert(op->getOut()->getSize() == 1);
    bool legacyReturnExtension = false;
    for (auto iter = function->beginOpAlive(); iter != function->endOpAlive(); ++iter) {
        PcodeOp *extension = *iter;
        if (extension->code() == CPUI_INT_ZEXT && extension->getIn(0)->getSize() == 1 &&
            extension->getOut()->getSize() == 8)
            legacyReturnExtension = true;
    }
    assert(legacyReturnExtension);
}

std::vector<ParameterPieces> allocate(Architecture &arch, ProtoModel &model,
    const std::vector<Datatype *> &inputs, int firstVarArg) {
    PrototypePieces pieces;
    pieces.model = &model;
    pieces.outtype = arch.types->getBase(4, TYPE_INT);
    pieces.intypes = inputs;
    pieces.firstVarArgSlot = firstVarArg;
    std::vector<ParameterPieces> result;
    model.assignParameterStorage(pieces, result, false);
    return result;
}

void checkPackingAndPromotions(Architecture &arch, ProtoModel &model) {
    Datatype *byte = arch.types->getBase(1, TYPE_INT);
    Datatype *half = arch.types->getBase(2, TYPE_INT);
    Datatype *word = arch.types->getBase(4, TYPE_INT);
    Datatype *wide = arch.types->getBase(8, TYPE_INT);
    std::vector<Datatype *> fixed(8, wide);
    fixed.insert(fixed.end(), {byte, half});
    auto result = allocate(arch, model, fixed, -1);
    assert(result[9].addr == Address(arch.getStackSpace(), 0) && result[9].type == byte);
    assert(result[10].addr == Address(arch.getStackSpace(), 2) && result[10].type == half);
    result = allocate(arch, model, {byte, word, word}, 1);
    assert(result[1].addr == arch.translate->getRegister("x0").getAddr() && result[1].type == byte);
    assert(result[2].addr == Address(arch.getStackSpace(), 0) && result[2].type == word);
    assert(result[3].addr == Address(arch.getStackSpace(), 8) && result[3].type == word);
    for (int index : {2, 3}) {
        VarnodeData extension;
        assert(model.assumedInputExtension(result[index].addr, 4, extension) == CPUI_COPY);
    }
}

ParamEntry decodeEntry(AddrSpaceManager &spaces, const std::string &xml) {
    XmlDecode decoder(&spaces);
    std::istringstream document(xml);
    decoder.ingestStream(document);
    std::list<ParamEntry> entries;
    entries.emplace_back(0);
    entries.back().decode(decoder, true, false, entries);
    return entries.back();
}

void checkWidthValidation(Architecture &arch) {
    ParamEntry undecoded(0);
    assert(!undecoded.isExtensionBounded());
    for (const char *width : {"", "0", "-1", "9", "4x", "4.0", "4294967300", "9223372036854775808"}) {
        bool rejected = false;
        try {
            decodeEntry(arch, std::string("<pentry minsize=\"1\" maxsize=\"8\" extension=\"inttype\" extension_size=\"")
                + width + "\"><register name=\"x0\"/></pentry>");
        } catch (const LowlevelError &) {
            rejected = true;
        }
        assert(rejected);
    }
    for (const char *extension : {"none", "float"}) {
        bool rejected = false;
        try {
            decodeEntry(arch, std::string("<pentry minsize=\"1\" maxsize=\"8\" extension=\"")
                + extension + "\" extension_size=\"4\"><register name=\"x0\"/></pentry>");
        } catch (const LowlevelError &) {
            rejected = true;
        }
        assert(rejected);
    }
    std::ostringstream overflowing;
    overflowing << "<pentry minsize=\"1\" maxsize=\"8\" extension=\"inttype\" extension_size=\"4\">"
        << "<addr space=\"register\" offset=\"0x" << std::hex
        << arch.translate->getRegister("x0").space->getHighest() << "\"/></pentry>";
    for (const std::string &xml : {
        std::string("<pentry minsize=\"1\" maxsize=\"16\" align=\"2\" extension=\"inttype\" extension_size=\"4\">")
            + "<addr space=\"register\" offset=\"0x1000\"/></pentry>",
        std::string("<pentry minsize=\"1\" maxsize=\"8\" align=\"16\" extension=\"inttype\" extension_size=\"12\">")
            + "<register name=\"x0\"/></pentry>",
        std::string("<pentry minsize=\"1\" maxsize=\"8\" align=\"16\" extension=\"inttype\" extension_size=\"4\">")
            + "<addr space=\"register\" offset=\"0x1000\"/></pentry>",
        std::string("<pentry minsize=\"1\" maxsize=\"10\" align=\"8\" extension=\"inttype\" extension_size=\"4\">")
            + "<addr space=\"register\" offset=\"0x1000\"/></pentry>",
        overflowing.str()}) {
        bool rejected = false;
        try {
            decodeEntry(arch, xml);
        } catch (const LowlevelError &) {
            rejected = true;
        }
        assert(rejected);
    }
    bool outputRejected = false;
    try {
        XmlDecode decoder(&arch);
        std::istringstream document(
            "<output><pentry minsize=\"1\" maxsize=\"8\" extension=\"inttype\" extension_size=\"4\">"
            "<register name=\"x0\"/></pentry></output>");
        decoder.ingestStream(document);
        ParamListStandardOut output;
        std::vector<EffectRecord> effects;
        output.decode(decoder, effects, true);
    } catch (const LowlevelError &error) {
        outputRejected = error.explain.find("only supported for input") != std::string::npos;
    }
    assert(outputRejected);
    ParamEntry entry = decodeEntry(arch,
        "<pentry minsize=\"1\" maxsize=\"8\" extension=\"inttype\" extension_size=\"4\">"
        "<register name=\"x0\"/></pentry>");
    const VarnodeData &x0 = arch.translate->getRegister("x0");
    VarnodeData extension;
    assert(entry.assumedExtension(x0.getAddr(), 0, extension) == CPUI_COPY);
    assert(entry.assumedExtension(x0.getAddr(), -1, extension) == CPUI_COPY);
    assert(entry.assumedExtension(x0.getAddr() + 1, 1, extension) == CPUI_COPY);
    assert(entry.assumedExtension(x0.getAddr() + 7, 2, extension) == CPUI_COPY);
    assert(entry.assumedExtension(Address(x0.space, x0.space->getHighest()), 2, extension) == CPUI_COPY);
    assert(entry.assumedExtension(Address(arch.getDefaultCodeSpace(), x0.offset), 1, extension) == CPUI_COPY);
    ParamEntry aligned = decodeEntry(arch,
        "<pentry minsize=\"1\" maxsize=\"16\" align=\"8\" extension=\"inttype\" extension_size=\"4\">"
        "<addr space=\"register\" offset=\"0x1000\"/></pentry>");
    assert(aligned.assumedExtension(Address(x0.space, 0x1000), 1, extension) == CPUI_PIECE);
    assert(extension.offset == 0x1000 && extension.size == 4);
    assert(aligned.assumedExtension(Address(x0.space, 0x1008), 1, extension) == CPUI_PIECE);
    assert(extension.offset == 0x1008 && extension.size == 4);
    assert(aligned.assumedExtension(Address(x0.space, 0x1010), 1, extension) == CPUI_COPY);
    assert(aligned.assumedExtension(Address(x0.space, 0x1007), 2, extension) == CPUI_COPY);
    ParamEntry boundary = decodeEntry(arch,
        "<pentry minsize=\"1\" maxsize=\"8\" align=\"8\" extension=\"inttype\" extension_size=\"4\">"
        "<register name=\"x0\"/></pentry>");
    assert(boundary.getSize() == 8 && boundary.getAlign() == 0);
    assert(boundary.assumedExtension(x0.getAddr(), 1, extension) == CPUI_PIECE);
    assert(extension.getAddr() == x0.getAddr() && extension.size == 4);
}

void checkBigEndianWindows() {
    OwnedEndianSpaces spaces;
    AddrSpace *actual = spaces.getSpaceByName("be_actual");
    AddrSpace *reverse = spaces.getSpaceByName("be_reverse");
    assert(actual->isBigEndian() && !actual->isReverseJustified());
    assert(reverse->isBigEndian() && reverse->isReverseJustified());
    ParamEntry bounded = decodeEntry(spaces,
        "<pentry minsize=\"1\" maxsize=\"8\" extension=\"inttype\" extension_size=\"4\">"
        "<addr space=\"be_actual\" offset=\"0x1000\"/></pentry>");
    VarnodeData extension;
    for (int4 size : {1, 2}) {
        assert(bounded.assumedExtension(Address(actual, 0x1008-size), size, extension) == CPUI_PIECE);
        assert(extension.space == actual && extension.offset == 0x1004 && extension.size == 4);
    }
    assert(bounded.assumedExtension(Address(actual, 0x1000), 1, extension) == CPUI_COPY);
    assert(bounded.assumedExtension(Address(actual, 0x1004), 4, extension) == CPUI_COPY);
    assert(bounded.assumedExtension(Address(actual, 0x1000), 8, extension) == CPUI_COPY);
    ParamEntry aligned = decodeEntry(spaces,
        "<pentry minsize=\"1\" maxsize=\"16\" align=\"8\" extension=\"inttype\" extension_size=\"4\">"
        "<addr space=\"be_actual\" offset=\"0x1000\"/></pentry>");
    assert(aligned.assumedExtension(Address(actual, 0x100f), 1, extension) == CPUI_PIECE);
    assert(extension.space == actual && extension.offset == 0x100c && extension.size == 4);
    bool reverseRejected = false;
    try {
        decodeEntry(spaces,
            "<pentry minsize=\"1\" maxsize=\"8\" extension=\"inttype\" extension_size=\"4\">"
            "<addr space=\"be_reverse\" offset=\"0x1000\"/></pentry>");
    } catch (const LowlevelError &error) {
        reverseRejected = error.explain.find("reverse-justified") != std::string::npos;
    }
    assert(reverseRejected);
    ParamEntry legacyActual = decodeEntry(spaces,
        "<pentry minsize=\"1\" maxsize=\"8\" extension=\"inttype\">"
        "<addr space=\"be_actual\" offset=\"0x1000\"/></pentry>");
    assert(legacyActual.assumedExtension(Address(actual, 0x1007), 1, extension) == CPUI_PIECE);
    assert(extension.space == actual && extension.offset == 0x1000 && extension.size == 8);
    ParamEntry legacyReverse = decodeEntry(spaces,
        "<pentry minsize=\"1\" maxsize=\"8\" extension=\"inttype\">"
        "<addr space=\"be_reverse\" offset=\"0x1000\"/></pentry>");
    assert(legacyReverse.assumedExtension(Address(reverse, 0x1000), 1, extension) == CPUI_PIECE);
    assert(extension.space == reverse && extension.offset == 0x1000 && extension.size == 8);
}
}

int main(int argc, char **argv) try {
    assert(argc == 2);
    if (std::string(argv[1]) == "--caller-assembly") {
        for (const CallerInstruction &instruction : callerInstructions) puts(instruction.assembly);
        return 0;
    }
    auto apple = open(argv[1], "AARCH64:LE:64:v8A:apple");
    queryModel(*apple->arch, *apple->arch->defaultfp, true);
    checkPackingAndPromotions(*apple->arch, *apple->arch->defaultfp);
    {
        ProtoModel clone("apple_narrow_clone", *apple->arch->defaultfp);
        queryModel(*apple->arch, clone, true);
        checkPackingAndPromotions(*apple->arch, clone);
    }
    checkWidthValidation(*apple->arch);
    checkBigEndianWindows();
    checkLockedInputs(*apple, true);
    apple.reset();
    auto upper = open(argv[1], "AARCH64:LE:64:v8A:apple", {0x00, 0xfc, 0x60, 0xd3, 0xc0, 0x03, 0x5f, 0xd6});
    checkUnknownUpperBits(*upper);
    upper.reset();
    std::vector<uint8_t> callerCode;
    for (const CallerInstruction &instruction : callerInstructions) {
        for (int shift : {0, 8, 16, 24})
            callerCode.push_back(static_cast<uint8_t>(instruction.word >> shift));
    }
    auto caller = open(argv[1], "AARCH64:LE:64:v8A:apple", callerCode);
    checkCallSide(*caller);
    caller.reset();
    auto generic = open(argv[1], "AARCH64:LE:64:v8A:default");
    queryModel(*generic->arch, *generic->arch->defaultfp, false);
    checkLockedInputs(*generic, false);
    puts("Narrow input extension window, unknown upper bits, legacy defaults, packing and promotions passed");
} catch (const LowlevelError &error) {
    fprintf(stderr, "%s\n", error.explain.c_str());
    return 1;
}
