// A C ABI over Ghidra's decompiler library. One handle holds a SleighArchitecture with an in-memory image
// spanning the loaded program's executable segments, so many functions decompile from a single setup.

#include "libdecomp.hh"
#include "sleigh_arch.hh"
#include "loadimage.hh"
#include "funcdata.hh"
#include "printc.hh"
#include "grammar.hh"
#include "sleigh.hh"
#include "tokens.hh"
#include "results.hh"
#include "local_variables.hh"
#include "type_hints.hh"
#include "type_library.hh"

#include <cstdlib>
#include <algorithm>
#include <cstring>
#include <sstream>
#include <memory>
#include <vector>

using namespace ghidra;

namespace {

// A segment of program bytes placed at a virtual address.
struct Segment {
    uintb base;
    std::vector<uint1> bytes;
    uintb size;
    bool readable;
    bool executable;
    bool writable;
};

// Backed bytes and declared zero-fill share a mapping; unavailable addresses never become data.
class MemImage : public LoadImage {
    std::vector<Segment> segments;
    AddrSpace *spaceid = nullptr;

    const Segment *segmentAt(uintb address) const {
        auto next = std::upper_bound(segments.begin(), segments.end(), address,
            [](uintb address, const Segment &segment) { return address < segment.base; });
        if (next == segments.begin()) return nullptr;
        const Segment &segment = *--next;
        return address - segment.base < segment.size ? &segment : nullptr;
    }

    int4 readPrefix(uint1 *output, int4 size, const Address &address, bool instruction) const {
        if (size <= 0) return 0;
        uintb start = address.getOffset();
        int4 copied = 0;
        while (copied < size) {
            if (start > address.getSpace()->getHighest()
                || uintb(copied) > address.getSpace()->getHighest() - start) break;
            uintb at = start + copied;
            const Segment *segment = segmentAt(at);
            if (segment == nullptr || (instruction ? !segment->executable : !segment->readable)) break;
            uintb offset = at - segment->base;
            int4 amount = int4(std::min<uintb>(size - copied, segment->size - offset));
            uintb lastAvailable = address.getSpace()->getHighest() - at;
            if (uintb(amount - 1) > lastAvailable) amount = int4(lastAvailable + 1);
            if (output != nullptr) {
                size_t backed = offset < segment->bytes.size()
                    ? size_t(std::min<uintb>(amount, segment->bytes.size() - offset)) : 0;
                if (backed != 0) memcpy(output + copied, segment->bytes.data() + offset, backed);
                memset(output + copied + backed, 0, amount - backed);
            }
            copied += amount;
        }
        return copied;
    }

    void requireRange(int4 size, const Address &address, bool instruction) const {
        if (size < 0 || readPrefix(nullptr, size, address, instruction) != size) {
            std::ostringstream message;
            message << "Unavailable " << (instruction ? "instruction" : "data") << " at " << address.getOffset();
            throw DataUnavailError(message.str());
        }
    }

public:
    MemImage(std::vector<Segment> segs) : LoadImage("memory"), segments(std::move(segs)) {
        std::sort(segments.begin(), segments.end(),
            [](const Segment &a, const Segment &b) { return a.base < b.base; });
    }

    void attachToSpace(AddrSpace *id) { spaceid = id; }

    bool mapped(uintb address) const { return segmentAt(address) != nullptr; }
    bool backedCode(uintb address) const {
        const Segment *segment = segmentAt(address);
        return segment != nullptr && segment->executable && address - segment->base < segment->bytes.size();
    }
    bool dataRange(uintb address, uintb size) const {
        if (size == 0 || size - 1 > UINT64_MAX - address) return false;
        uintb copied = 0;
        while (copied < size) {
            const Segment *segment = segmentAt(address + copied);
            if (segment == nullptr || segment->executable) return false;
            copied += std::min<uintb>(size - copied, segment->size - (address + copied - segment->base));
        }
        return true;
    }

    void loadFill(uint1 *ptr, int4 size, const Address &addr) override {
        if (size < 0 || readPrefix(ptr, size, addr, false) != size)
            throw DataUnavailError("Data range is unavailable");
    }

    void loadInstruction(uint1 *ptr, int4 size, const Address &addr) override {
        requireRange(1, addr, true);
        memset(ptr, 0, size);
        readPrefix(ptr, size, addr, true);
    }

    void validateInstruction(int4 size, const Address &addr) override {
        requireRange(size, addr, true);
    }

    int4 loadString(uint1 *ptr, int4 size, const Address &addr) override {
        int4 copied = readPrefix(ptr, size, addr, false);
        if (copied == 0) throw DataUnavailError("String address is unavailable");
        return copied;
    }

    void getReadonly(RangeList &list) const override {
        if (spaceid == nullptr) return;
        for (const Segment &seg : segments) {
            if (seg.readable && !seg.writable && seg.size != 0) {
                list.insertRange(spaceid, seg.base, seg.base + seg.size - 1);
            }
        }
    }

    string getArchType(void) const override { return "memory"; }
    void adjustVma(long adjust) override {}
};

// Mirrors RawBinaryArchitecture, but takes its bytes from a MemImage we own until init hands it over.
class MemArchitecture : public SleighArchitecture {
    MemImage *image;

    Translate *buildTranslator(DocumentStorage &store) override {
        // restoreFromSpec owns this pointer until initialization assigns Architecture::translate.
        return new Sleigh(loader, context);
    }

    void buildLoader(DocumentStorage &store) override {
        collectSpecFiles(*errorstream);
        loader = image;
    }
    void resolveArchitecture(void) override {
        archid = getTarget();
        size_t separator = archid.rfind(':');
        string languageId = archid.substr(0, separator);
        string compilerId = archid.substr(separator + 1);
        bool found = false;
        for (const LanguageDescription &language : getDescriptions()) {
            if (language.getId() != languageId) continue;
            for (int4 i = 0; i < language.numCompilers(); ++i) {
                if (language.getCompiler(i).getId() == compilerId) found = true;
            }
        }
        if (!found) throw LowlevelError("Unknown processor/compiler specification: " + archid);
        SleighArchitecture::resolveArchitecture();
    }
    void postSpecFile(void) override {
        Architecture::postSpecFile();
        image->attachToSpace(getDefaultCodeSpace());
    }

public:
    MemArchitecture(const string &target, MemImage *img, ostream *estream)
        : SleighArchitecture("memory", target, estream), image(img) {}

    const string &selectedLanguage() const { return archid; }

    void resetTranslationCache() {
        const_cast<Sleigh *>(static_cast<const Sleigh *>(translate))->clearCache();
    }

    bool mapped(uintb address) const { return image->mapped(address); }
    bool dataRange(uintb address, uintb size) const { return image->dataRange(address, size); }
    bool backedCode(uintb address) const { return image->backedCode(address); }

    // Until buildLoader hands the image to `loader` (which the base destructor frees), we still own it. This
    // keeps ownership correct when init fails partway, so the error path neither leaks nor double-frees.
    ~MemArchitecture() override {
        delete translate;
        translate = nullptr;
        if (loader != image) delete image;
    }
};

struct Handle {
    MemArchitecture *arch = nullptr;
    rampage::TokenEmitter *emitter = nullptr;
    std::string error;
    uintb nextExternal = 0;
    std::map<uintb, ExternRefSymbol *> imports;
    std::map<uintb, uintb> externalSlots;
    std::vector<rampage::Token> tokens;
    std::string results;
    std::string typeResult;
    std::map<Datatype *, int4> typePacking;
    std::map<uintb, std::vector<rampage::LocalOverride>> localOverrides;
    std::map<uintb, std::vector<rampage::TypeHint>> typeHints;
    std::map<uintb, rampage::CalleeTypeShape> calleeTypeShapes;
    bool preparingTypeHintContext = false;
    bool poisoned = false;
    bool fallbackError = false;
    bool unsafeCleanup = false;
};

// Fixed flat records shared with layout.rs, not a serialization of Ghidra's type graph.
constexpr size_t layoutMaxFields = 128;
constexpr size_t layoutMaxName = 128;
constexpr size_t layoutMaxText = 32768;
constexpr uint32_t layoutMaxSize = 1048576;

struct LayoutScalar {
    uint8_t name[layoutMaxName + 1];
    uint32_t kind;
    uint32_t size;
    uint32_t alignment;
};

struct LayoutField {
    uint8_t name[layoutMaxName + 1];
    uint8_t typeName[layoutMaxName + 1];
    uint32_t offset;
    uint32_t size;
    uint32_t alignment;
    uint32_t pointer;
    LayoutScalar scalar;
};

struct PlainLayout {
    uint8_t name[layoutMaxName + 1];
    uint32_t size;
    uint32_t alignment;
    uint32_t pointerSize;
    uint32_t intSize;
    uint32_t longSize;
    uint32_t scalarAlignments[4];
    uint32_t count;
    LayoutField fields[layoutMaxFields];
};

bool layoutIdentifier(const char *name, size_t length, bool empty = false) {
    if (length == 0) return empty;
    if (length > layoutMaxName) return false;
    auto letter = [](unsigned char ch) { return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_'; };
    if (!letter(name[0])) return false;
    for (size_t i = 1; i < length; ++i) {
        unsigned char ch = name[i];
        if (!letter(ch) && !(ch >= '0' && ch <= '9')) return false;
    }
    return true;
}

void layoutName(uint8_t *output, const string &name, size_t &budget, bool empty = false) {
    if (!layoutIdentifier(name.data(), name.size(), empty))
        throw LowlevelError("Plain-struct layout has an invalid or over-budget name");
    if (name.size() > layoutMaxText - budget)
        throw LowlevelError("Plain-struct layout cumulative name/type byte limit exceeded");
    budget += name.size();
    memcpy(output, name.data(), name.size());
    output[name.size()] = 0;
}

bool layoutAlignment(int4 alignment) {
    return alignment > 0 && alignment <= 8 && (alignment & (alignment - 1)) == 0;
}

void inspectLayoutScalar(Datatype *type, LayoutScalar &output, size_t &budget, bool allowVoid) {
    if (type == nullptr || type->isIncomplete() || type->hasBitfields() || type->hasWarning()
        || type->isEnumType() || type->hasStripped() || type->numDepend() != 0)
        throw LowlevelError("Plain-struct layout requires complete plain scalar leaves");
    int4 size = type->getSize();
    int4 alignment = type->getAlignment();
    if (!layoutAlignment(alignment) || size < 0)
        throw LowlevelError("Plain-struct layout has invalid scalar size/alignment");
    switch (type->getMetatype()) {
    case TYPE_VOID:
        if (!allowVoid || size != 0 || alignment != 1)
            throw LowlevelError("Plain-struct layout does not permit a void field");
        output.kind = 0;
        break;
    case TYPE_INT:
    case TYPE_UINT:
        if (size != 1 && size != 2 && size != 4 && size != 8)
            throw LowlevelError("Plain-struct layout has an unsupported integer width");
        if (type->isASCII()) {
            if (size != 1) throw LowlevelError("Plain-struct layout has an unsupported character width");
            output.kind = type->getMetatype() == TYPE_INT ? 3 : 4;
        } else {
            if (type->isCharPrint()) throw LowlevelError("Plain-struct layout does not support wide/opaque characters");
            output.kind = type->getMetatype() == TYPE_INT ? 1 : 2;
        }
        break;
    case TYPE_FLOAT:
        if (size != 4 && size != 8) throw LowlevelError("Plain-struct layout has an unsupported float width");
        output.kind = 5;
        break;
    case TYPE_BOOL:
        if (size != 1) throw LowlevelError("Plain-struct layout has an unsupported boolean width");
        output.kind = 6;
        break;
    default:
        throw LowlevelError("Plain-struct layout does not support aggregate/array/code/pointer/unknown leaves");
    }
    if (size != 0 && (alignment > size || type->getAlignSize() != size))
        throw LowlevelError("Plain-struct layout has an unsupported padded scalar");
    layoutName(output.name, type->getName(), budget);
    output.size = size;
    output.alignment = alignment;
}

PlainLayout inspectPlainLayout(MemArchitecture *arch, const string &name) {
    TypeFactory *types = arch->types;
    AddrSpace *space = arch->getDefaultDataSpace();
    if (space->isBigEndian() || space->getWordSize() != 1 || space->getAddrSize() != 8
        || types->getSizeOfPointer() != 8 || types->getSizeOfInt() != 4
        || types->getSizeOfLong() != 8 || types->getSizeOfChar() != 1)
        throw LowlevelError("Plain-struct layout requires x86-64 little-endian LP64 byte-addressed organization");
    Datatype *type = types->findByName(name);
    if (type == nullptr || type->getMetatype() != TYPE_STRUCT || type->isIncomplete()
        || type->hasWarning() || type->hasBitfields() || type->getSize() <= 0
        || type->getSize() > layoutMaxSize || !layoutAlignment(type->getAlignment())
        || type->getAlignSize() != type->getSize())
        throw LowlevelError("Plain-struct layout requires a complete bounded struct without bitfields");
    TypeStruct *structure = static_cast<TypeStruct *>(type);
    size_t count = size_t(structure->endField() - structure->beginField());
    if (count == 0 || count > layoutMaxFields || structure->numBitFields() != 0)
        throw LowlevelError("Plain-struct layout field count/bitfield limit exceeded");
    PlainLayout result = {};
    size_t budget = 0;
    layoutName(result.name, type->getName(), budget);
    result.size = type->getSize();
    result.alignment = type->getAlignment();
    result.pointerSize = types->getSizeOfPointer();
    result.intSize = types->getSizeOfInt();
    result.longSize = types->getSizeOfLong();
    for (size_t i = 0; i < 4; ++i) {
        int4 alignment = types->getAlignment(uint4(1) << i);
        if (!layoutAlignment(alignment)) throw LowlevelError("Plain-struct layout has unsupported native alignments");
        result.scalarAlignments[i] = alignment;
    }
    uint32_t previousEnd = 0;
    for (auto field = structure->beginField(); field != structure->endField(); ++field) {
        LayoutField &output = result.fields[result.count];
        Datatype *leaf = field->type;
        if (leaf == nullptr || leaf->isIncomplete() || leaf->hasBitfields() || leaf->hasWarning()
            || leaf->getSize() <= 0 || leaf->getSize() > layoutMaxSize
            || !layoutAlignment(leaf->getAlignment()) || field->offset < 0)
            throw LowlevelError("Plain-struct layout has an invalid field type/offset/size");
        output.offset = field->offset;
        output.size = leaf->getSize();
        output.alignment = leaf->getAlignment();
        if (output.offset < previousEnd || output.offset > result.size
            || output.size > result.size - output.offset || output.offset % output.alignment != 0
            || output.alignment > result.alignment)
            throw LowlevelError("Plain-struct layout field overlaps or exceeds its struct/alignment");
        previousEnd = output.offset + output.size;
        layoutName(output.name, field->name, budget);
        for (uint32_t i = 0; i < result.count; ++i) {
            if (strcmp(reinterpret_cast<const char *>(output.name),
                       reinterpret_cast<const char *>(result.fields[i].name)) == 0)
                throw LowlevelError("Plain-struct layout has duplicate field names");
        }
        if (leaf->getMetatype() == TYPE_PTR) {
            TypePointer *pointer = static_cast<TypePointer *>(leaf);
            if (pointer->getWordSize() != 1 || pointer->getSpace() != nullptr || leaf->isPointerRel()
                || leaf->isPointerToArray() || leaf->hasStripped() || output.size != result.pointerSize
                || leaf->getAlignSize() != leaf->getSize())
                throw LowlevelError("Plain-struct layout requires a native-width ordinary pointer");
            output.pointer = 1;
            layoutName(output.typeName, leaf->getName(), budget, true);
            inspectLayoutScalar(pointer->getPtrTo(), output.scalar, budget, true);
        } else {
            inspectLayoutScalar(leaf, output.scalar, budget, false);
        }
        ++result.count;
    }
    return result;
}

const char *handleError(const Handle *handle) noexcept {
    if (handle->fallbackError) return "Native decompiler failed; handle is unavailable";
    return handle->error.empty() ? nullptr : handle->error.c_str();
}

const char *setError(Handle *handle, const char *message, bool poison = false) noexcept {
    handle->poisoned |= poison;
    handle->fallbackError = true;
    try {
        handle->error = message;
        handle->fallbackError = false;
    } catch (...) { handle->poisoned = true; }
    if (handle->poisoned) {
        handle->tokens.clear();
        handle->results.clear();
    }
    return handleError(handle);
}

template <typename Operation>
const char *mutate(Handle *handle, Operation operation) noexcept {
    if (handle->arch == nullptr || handle->poisoned) return "Decompiler handle is unavailable";
    bool nativeMutation = false;
    try {
        operation(nativeMutation);
        handle->error.clear();
        handle->fallbackError = false;
        return nullptr;
    } catch (const LowlevelError &error) {
        return setError(handle, error.explain.c_str());
    } catch (const DecoderError &error) {
        handle->unsafeCleanup |= nativeMutation;
        return setError(handle, error.explain.c_str(), true);
    } catch (const std::exception &error) {
        handle->unsafeCleanup |= nativeMutation;
        return setError(handle, error.what(), true);
    } catch (...) {
        handle->unsafeCleanup |= nativeMutation;
        return setError(handle, "Unexpected native decompiler exception", true);
    }
}

struct DeleteArchitecture {
    void operator()(MemArchitecture *arch) const noexcept {
        try { delete arch; } catch (...) {}
    }
};

void failDecompilation(Handle *handle, Funcdata *function, const char *message, bool recover) noexcept {
    setError(handle, message, true);
    if (handle->unsafeCleanup) return;
    try {
        handle->arch->print->setOutputStream(nullptr);
        handle->arch->print->clear();
        if (recover && !handle->fallbackError) {
            if (function != nullptr) handle->arch->clearAnalysis(function);
            handle->poisoned = false;
        }
    } catch (...) { handle->unsafeCleanup = true; }
}

struct DetachOutput {
    rampage::TokenEmitter *emitter;
    ~DetachOutput() noexcept { emitter->EmitNoMarkup::setOutputStream(nullptr); }
};

class LimitedOutput : public std::streambuf {
    std::string data;
protected:
    pos_type seekoff(off_type offset, std::ios_base::seekdir direction,
                     std::ios_base::openmode mode) override {
        if (offset == 0 && direction == std::ios_base::cur && mode == std::ios_base::out)
            return pos_type(data.size());
        return pos_type(off_type(-1));
    }
    pos_type seekpos(pos_type position, std::ios_base::openmode mode) override {
        if (position == pos_type(data.size()) && mode == std::ios_base::out) return position;
        return pos_type(off_type(-1));
    }
    int_type overflow(int_type character) override {
        if (traits_type::eq_int_type(character, traits_type::eof())) return traits_type::not_eof(character);
        if (data.size() >= 4 * 1024 * 1024) throw LowlevelError("Decompiler output limit exceeded");
        data.push_back(traits_type::to_char_type(character));
        return character;
    }
    std::streamsize xsputn(const char *text, std::streamsize count) override {
        if (count < 0 || uint64_t(count) > 4 * 1024 * 1024 - data.size())
            throw LowlevelError("Decompiler output limit exceeded");
        data.append(text, count);
        return count;
    }
public:
    const std::string &str() const { return data; }
};

void ensureDecompilerStarted(const char *home) {
    static bool started = false;
    static bool failed = false;
    if (failed) throw LowlevelError("Decompiler library initialization failed; restart required");
    if (started) return;
    failed = true;
    startDecompilerLibrary(home);
    started = true;
    failed = false;
}

constexpr size_t decodeMaxOps = 128;
constexpr size_t decodeMaxInputs = 16;
constexpr size_t decodeMaxSpaces = 32;
constexpr size_t decodeMaxWindow = 65536;

struct DecodeSpace {
    uint32_t id, kind, addressSize, wordSize;
    uint64_t highest;
    char name[64];
};

struct DecodeMetadata {
    uint32_t status, alignment, spaceCount, codeSpace;
    char error[256];
    char processorHelper[256];
    DecodeSpace spaces[decodeMaxSpaces];
};

struct DecodeNode {
    uint32_t space, size;
    uint64_t offset;
    uint32_t selector, selectorSpace;
};

struct DecodeOp {
    uint32_t opcode, inputCount, hasOutput;
    char name[32];
    uint64_t address;
    DecodeNode output;
    DecodeNode inputs[decodeMaxInputs];
};

struct DecodeResult {
    uint32_t status, length, extent, opCount, spaceCount, codeSpace;
    uint32_t contextMediatedFlow;
    uint32_t processorHelperRequired;
    char mnemonic[256];
    char operands[3840];
    char error[256];
    DecodeSpace spaces[decodeMaxSpaces];
    DecodeOp ops[decodeMaxOps];
};

struct DecodeLimit : public std::exception {};

template<size_t N> void decodeText(char (&output)[N], const string &text) {
    if (text.size() >= N) throw DecodeLimit();
    memcpy(output, text.data(), text.size());
    output[text.size()] = 0;
}

// This loader deliberately does not share MemImage's data/zero-fill semantics.
class DecodeImage : public LoadImage {
public:
    AddrSpace *code = nullptr;
    uintb base = 0;
    std::vector<uint1> bytes;
    bool padded = false;
    DecodeImage() : LoadImage("instruction-window") {}

    void require(int4 size, const Address &address) const {
        if (address.getSpace() != code || size <= 0 || address.getOffset() < base)
            throw DataUnavailError("Instruction window is unavailable");
        uintb offset = address.getOffset() - base;
        if (offset >= bytes.size() || uintb(size) > bytes.size() - offset)
            throw DataUnavailError("Instruction extends beyond backed executable bytes");
    }

    void loadInstruction(uint1 *output, int4 size, const Address &address) override {
        require(1, address);
        if (size < 0 || size_t(size) > decodeMaxWindow) throw DecodeLimit();
        size_t offset = size_t(address.getOffset() - base);
        size_t amount = std::min<size_t>(size, bytes.size() - offset);
        memcpy(output, bytes.data() + offset, amount);
        memset(output + amount, 0, size_t(size) - amount);
        padded = padded || amount != size_t(size);
    }

    void validateInstruction(int4 size, const Address &address) override {
        if (size > 16) throw BadDataError("Instruction exceeds the 16-byte parser buffer");
        require(size, address);
    }
    void loadFill(uint1 *, int4, const Address &) override {
        throw DataUnavailError("Instruction decoder cannot read data or unrelated address spaces");
    }
    string getArchType() const override { return "instruction-window"; }
    void adjustVma(long) override {}
};

class DecodeSleigh : public Sleigh {
public:
    DecodeSleigh(LoadImage *image, ContextDatabase *context) : Sleigh(image, context) {}
    bool hasContextCommits(const Address &address) const {
        return obtainContext(address, ParserContext::disassembly)->hasContextCommits();
    }
};

struct DecodeHandle {
    DecodeImage image;
    ContextInternal context;
    std::unique_ptr<DecodeSleigh> sleigh;
    char error[256]{};
    std::string processorHelper;
};

void decodeError(char *output, const char *message) noexcept {
    if (message == nullptr) message = "Unknown native decoder error";
    size_t length = 0;
    while (length < 255 && message[length] != 0) ++length;
    memcpy(output, message, length);
    output[length] = 0;
}

class DecodeAssembly : public AssemblyEmit {
    DecodeResult &result;
public:
    explicit DecodeAssembly(DecodeResult &output) : result(output) {}
    void dump(const Address &, const string &mnemonic, const string &operands) override {
        decodeText(result.mnemonic, mnemonic);
        decodeText(result.operands, operands);
    }
};

class DecodePcode : public PcodeEmit {
    DecodeResult &result;
    const Sleigh &sleigh;

    uint32_t spaceId(AddrSpace *space) const {
        for (int4 i = 0; i < sleigh.numSpaces(); ++i) {
            if (sleigh.getSpace(i) == space) return uint32_t(i);
        }
        throw LowlevelError("P-code refers to an unknown address-space identity");
    }

    DecodeNode node(const VarnodeData &value, bool selector) const {
        DecodeNode output{};
        output.space = spaceId(value.space);
        output.size = value.size;
        if (selector) {
            if (value.space != sleigh.getConstantSpace())
                throw LowlevelError("LOAD/STORE space selector is not a constant");
            output.selector = 1;
            output.selectorSpace = spaceId(value.getSpaceFromConst());
        } else output.offset = value.offset;
        return output;
    }

public:
    DecodePcode(DecodeResult &output, const Sleigh &translator) : result(output), sleigh(translator) {}
    void dump(const Address &address, OpCode opcode, VarnodeData *output,
              VarnodeData *inputs, int4 count) override {
        if (result.opCount >= decodeMaxOps || count < 0 || size_t(count) > decodeMaxInputs)
            throw DecodeLimit();
        DecodeOp &op = result.ops[result.opCount++];
        op.opcode = uint32_t(opcode);
        decodeText(op.name, get_opname(opcode));
        op.address = address.getOffset();
        op.inputCount = uint32_t(count);
        op.hasOutput = output != nullptr;
        if (output != nullptr) op.output = node(*output, false);
        for (int4 i = 0; i < count; ++i)
            op.inputs[i] = node(inputs[i], i == 0 && (opcode == CPUI_LOAD || opcode == CPUI_STORE));
    }
};

template<typename Result> void decodeSpaces(const Sleigh &sleigh, Result &result) {
    if (sleigh.numSpaces() < 0 || size_t(sleigh.numSpaces()) > decodeMaxSpaces) throw DecodeLimit();
    result.spaceCount = uint32_t(sleigh.numSpaces());
    for (int4 i = 0; i < sleigh.numSpaces(); ++i) {
        AddrSpace *space = sleigh.getSpace(i);
        if (space == nullptr) continue;
        DecodeSpace &out = result.spaces[i];
        out.id = uint32_t(i);
        out.kind = uint32_t(space->getType());
        out.addressSize = uint32_t(space->getAddrSize());
        out.wordSize = uint32_t(space->getWordSize());
        out.highest = space->getHighest();
        decodeText(out.name, space->getName());
        if (space == sleigh.getDefaultCodeSpace()) result.codeSpace = uint32_t(i);
    }
}

} // namespace

extern "C" {

size_t rampage_sleigh_result_size() noexcept { return sizeof(DecodeResult); }

size_t rampage_sleigh_metadata_size() noexcept { return sizeof(DecodeMetadata); }

void rampage_sleigh_metadata(void *pointer, DecodeMetadata *result) noexcept {
    if (result == nullptr) return;
    memset(result, 0, sizeof(*result));
    result->status = 1;
    DecodeHandle *handle = static_cast<DecodeHandle *>(pointer);
    if (handle == nullptr || handle->error[0] != 0 || !handle->sleigh) {
        decodeError(result->error, "Uninitialized instruction decoder");
        return;
    }
    try {
        int4 alignment = handle->sleigh->getAlignment();
        if (alignment <= 0) throw LowlevelError("Invalid instruction alignment");
        decodeSpaces(*handle->sleigh, *result);
        result->alignment = uint32_t(alignment);
        decodeText(result->processorHelper, handle->processorHelper);
        result->status = 0;
    } catch (const DecodeLimit &) {
        decodeError(result->error, "Decoder metadata budget exceeded");
    } catch (const LowlevelError &error) {
        decodeError(result->error, error.explain.c_str());
    } catch (const std::exception &error) {
        decodeError(result->error, error.what());
    } catch (...) {
        decodeError(result->error, "Unexpected native decoder metadata exception");
    }
}


// Paths here are private Rust ABI inputs selected only from the verified embedded registry.
void *rampage_sleigh_open(const char *home, const char *sla, const char *pspec) noexcept {
    std::unique_ptr<DecodeHandle> handle;
    try {
        handle.reset(new DecodeHandle());
        ensureDecompilerStarted(home);
        handle->sleigh.reset(new DecodeSleigh(&handle->image, &handle->context));
        std::ostringstream xml;
        xml << "<sleigh>";
        xml_escape(xml, sla);
        xml << "</sleigh>";
        std::istringstream source(xml.str());
        DocumentStorage store;
        store.registerTag(store.parseDocument(source)->getRoot());
        handle->sleigh->initialize(store);
        Document *processor = store.openDocument(pspec);
        for (const Element *child : processor->getRoot()->getChildren()) {
            if (child->getName() == "properties") {
                for (const Element *property : child->getChildren()) {
                    if (property->getName() == "property"
                        && property->getAttributeValue("key") == "parallelInstructionHelperClass")
                        handle->processorHelper = property->getAttributeValue("value");
                }
            }
            if (child->getName() == "context_data") {
                XmlDecode decoder(handle->sleigh.get(), child);
                handle->context.decodeFromSpec(decoder);
            }
        }
        handle->image.code = handle->sleigh->getDefaultCodeSpace();
        handle->sleigh->allowContextSet(false);
    } catch (const LowlevelError &error) {
        if (handle) decodeError(handle->error, error.explain.c_str());
    } catch (const DecoderError &error) {
        if (handle) decodeError(handle->error, error.explain.c_str());
    } catch (const std::exception &error) {
        if (handle) decodeError(handle->error, error.what());
    } catch (...) {
        if (handle) decodeError(handle->error, "Unexpected native decoder initialization exception");
    }
    return handle.release();
}

const char *rampage_sleigh_error(void *pointer) noexcept {
    DecodeHandle *handle = static_cast<DecodeHandle *>(pointer);
    return handle->error[0] == 0 ? nullptr : handle->error;
}

// Status: valid, invalid, truncated, unavailable, unimplemented, limit, internal, ambiguous tail.
void rampage_sleigh_decode(void *pointer, uint64_t base, const uint8_t *bytes,
                          size_t size, DecodeResult *result) noexcept {
    if (result == nullptr) return;
    memset(result, 0, sizeof(*result));
    result->status = 6;
    DecodeHandle *handle = static_cast<DecodeHandle *>(pointer);
    if (handle == nullptr || handle->error[0] != 0 || !handle->sleigh) {
        decodeError(result->error, "Uninitialized instruction decoder");
        return;
    }
    try {
        handle->sleigh->clearCache();
        handle->sleigh->allowContextSet(false);
        handle->image.bytes.clear();
        handle->image.padded = false;
        if (size > decodeMaxWindow) throw DecodeLimit();
        decodeSpaces(*handle->sleigh, *result);
        result->processorHelperRequired = !handle->processorHelper.empty();
        if (size == 0 || bytes == nullptr || base > handle->image.code->getHighest()
            || size - 1 > handle->image.code->getHighest() - base) {
            result->status = 3;
            return;
        }
        handle->image.base = base;
        handle->image.bytes.assign(bytes, bytes + size);
        Address address(handle->image.code, base);
        if (base % handle->sleigh->getAlignment() != 0) {
            result->status = 1;
            decodeError(result->error, "Instruction address is not aligned");
            return;
        }
        int4 length = handle->sleigh->instructionLength(address);
        handle->image.require(length, address);
        result->length = uint32_t(length);
        result->contextMediatedFlow = handle->sleigh->hasContextCommits(address);
        DecodeAssembly assembly(*result);
        if (handle->sleigh->printAssembly(assembly, address) != length)
            throw LowlevelError("Inconsistent assembly instruction length");
        DecodePcode pcode(*result, *handle->sleigh);
        int4 extent = handle->sleigh->oneInstruction(pcode, address);
        result->contextMediatedFlow |= handle->sleigh->hasContextCommits(address);
        handle->image.require(extent, address);
        result->extent = uint32_t(extent);
        result->status = 0;
    } catch (const DecodeLimit &) {
        result->status = 5;
        decodeError(result->error, "Instruction decoder output or window budget exceeded");
    } catch (const UnimplError &error) {
        result->status = 4;
        if (error.instruction_length > 0) {
            if (size_t(error.instruction_length) <= handle->image.bytes.size())
                result->extent = uint32_t(error.instruction_length);
            else result->status = 2;
        }
        decodeError(result->error, error.explain.c_str());
    } catch (const DataUnavailError &error) {
        result->status = 2;
        decodeError(result->error, error.explain.c_str());
    } catch (const BadDataError &error) {
        result->status = handle->image.padded ? 7 : 1;
        decodeError(result->error, error.explain.c_str());
    } catch (const LowlevelError &error) {
        result->status = 6;
        decodeError(result->error, error.explain.c_str());
    } catch (const DecoderError &error) {
        result->status = 6;
        decodeError(result->error, error.explain.c_str());
    } catch (const std::exception &error) {
        result->status = 6;
        decodeError(result->error, error.what());
    } catch (...) {
        result->status = 6;
        decodeError(result->error, "Unexpected native instruction decoder exception");
    }
}

void rampage_sleigh_close(void *pointer) noexcept {
    try { delete static_cast<DecodeHandle *>(pointer); } catch (...) {}
}

// Private test probe against actual translator space identities, including Harvard code/mem/codebyte.
uint8_t rampage_sleigh_test_loader_isolation(void *pointer) noexcept {
    try {
        DecodeHandle *handle = static_cast<DecodeHandle *>(pointer);
        if (handle == nullptr || !handle->sleigh || handle->error[0] != 0) return 0;
        DecodeImage image;
        image.code = handle->sleigh->getDefaultCodeSpace();
        image.bytes.push_back(0xa5);
        uint1 output[16]{};
        image.loadInstruction(output, 16, Address(image.code, 0));
        if (output[0] != 0xa5 || !image.padded) return 0;
        image.validateInstruction(1, Address(image.code, 0));
        try {
            image.validateInstruction(2, Address(image.code, 0));
            return 0;
        } catch (const DataUnavailError &) {}
        for (int4 i = 0; i < handle->sleigh->numSpaces(); ++i) {
            AddrSpace *space = handle->sleigh->getSpace(i);
            if (space == nullptr) continue;
            try {
                image.loadFill(output, 1, Address(space, 0));
                return 0;
            } catch (const DataUnavailError &) {}
            if (space == image.code) continue;
            try {
                image.loadInstruction(output, 1, Address(space, 0));
                return 0;
            } catch (const DataUnavailError &) {}
            try {
                image.validateInstruction(1, Address(space, 0));
                return 0;
            } catch (const DataUnavailError &) {}
        }
        return 1;
    } catch (...) { return 0; }
}

uint8_t rampage_sleigh_test_parser_read(int32_t start, int32_t size, uint32_t offset,
                                      uint8_t bits, uint32_t *output) noexcept {
    if (output == nullptr) return 2;
    *output = 0;
    try {
        ParserContext parser(nullptr, nullptr);
        for (uint4 i = 0; i < 16; ++i) parser.getBuffer()[i] = uint1(i + 1);
        *output = bits != 0 ? parser.getInstructionBits(start, size, offset)
                            : parser.getInstructionBytes(start, size, offset);
        return 0;
    } catch (const BadDataError &) { return 1; }
    catch (...) { return 2; }
}

// Opens a decompiler over the given segments. `langid` is Ghidra's 5-part id, e.g. "x86:LE:64:default:gcc".
// Returns an error handle on failure, or null if the handle itself could not be allocated.
void *rampage_decomp_open(const char *sleighhome, const char *langid, size_t nseg, const uint64_t *bases,
                          const uint8_t *const *ptrs, const size_t *lens, const uint64_t *sizes,
                          const uint8_t *readable, const uint8_t *executable, const uint8_t *writable) noexcept {
    std::unique_ptr<Handle> handle;
    std::unique_ptr<MemArchitecture, DeleteArchitecture> arch;
    bool initializing = false;
    try {
        handle.reset(new Handle());
        ensureDecompilerStarted(sleighhome);
        std::vector<Segment> segments;
        for (size_t i = 0; i < nseg; ++i) {
            Segment seg;
            seg.base = bases[i];
            if (lens[i] != 0) seg.bytes.assign(ptrs[i], ptrs[i] + lens[i]);
            seg.size = sizes[i];
            seg.readable = readable[i] != 0;
            seg.executable = executable[i] != 0;
            seg.writable = writable[i] != 0;
            segments.push_back(std::move(seg));
        }
        std::unique_ptr<MemImage> image(new MemImage(std::move(segments)));
        arch.reset(new MemArchitecture(langid, image.get(), &std::cerr));
        image.release();
        DocumentStorage store;
        initializing = true;
        arch->init(store);
        initializing = false;
        std::unique_ptr<rampage::TokenEmitter> emitter(new rampage::TokenEmitter(handle->tokens));
        arch->print->setEmitter(emitter.get());
        handle->emitter = emitter.release();
        handle->nextExternal = arch->getDefaultCodeSpace()->getHighest();
        handle->arch = arch.release();
    } catch (const LowlevelError &error) {
        if (handle) setError(handle.get(), error.explain.c_str(), true);
    } catch (const DecoderError &error) {
        if (handle) setError(handle.get(), error.explain.c_str(), true);
    } catch (const std::exception &error) {
        if (handle) {
            handle->unsafeCleanup = initializing;
            handle->arch = arch.release();
            setError(handle.get(), error.what(), true);
        }
    } catch (...) {
        if (handle) {
            handle->unsafeCleanup = initializing;
            handle->arch = arch.release();
            setError(handle.get(), "Unexpected native decompiler exception", true);
        }
    }
    return handle.release();
}

// Registers a known function address with a name, so calls to it render by name rather than by address. Must be
// called before decompiling callers. Ignored on failure (e.g. an address outside any space).
void rampage_decomp_add_symbol(void *h, uint64_t addr, const char *name) noexcept {
    Handle *handle = static_cast<Handle *>(h);
    if (handle->arch == nullptr || handle->poisoned || name == nullptr || name[0] == '\0') return;
    mutate(handle, [&](bool &nativeMutation) {
        Architecture *arch = handle->arch;
        Address entry(arch->getDefaultCodeSpace(), addr);
        Scope *global = arch->symboltab->getGlobalScope();
        if (global->queryFunction(entry) == nullptr) {
            nativeMutation = true;
            global->addFunction(entry, name);
        }
    });
}

const char *rampage_decomp_symbol(void *h, uint64_t addr, const char *name) noexcept {
    Handle *handle = static_cast<Handle *>(h);
    return mutate(handle, [&](bool &nativeMutation) {
        Address entry(handle->arch->getDefaultCodeSpace(), addr);
        Scope *global = handle->arch->symboltab->getGlobalScope();
        Funcdata *function = global->queryFunction(entry);
        nativeMutation = true;
        if (function == nullptr) global->addFunction(entry, name);
        else {
            global->renameSymbol(function->getSymbol(), name);
            function->setDisplayName(name);
        }
    });
}

const char *rampage_decomp_import(void *h, uint64_t slot, uint64_t target, uint8_t hasTarget,
                                const char *name) noexcept {
    Handle *handle = static_cast<Handle *>(h);
    return mutate(handle, [&](bool &nativeMutation) {
        AddrSpace *space = handle->arch->getDefaultCodeSpace();
        Scope *global = handle->arch->symboltab->getGlobalScope();
        if (handle->imports.find(slot) != handle->imports.end())
            throw LowlevelError("Import slot is already registered");
        if (hasTarget == 0) {
            uintb size = handle->arch->min_funcsymbol_size;
            if (handle->nextExternal < size) throw LowlevelError("No address available for external function");
            uintb candidate = (handle->nextExternal - (size - 1)) / size * size;
            bool free = false;
            uintb attempts = 0;
            while (candidate >= size && !free && attempts++ < 65536) {
                free = global->findOverlap(Address(space, candidate), size) == nullptr;
                for (uintb offset = 0; offset < size; ++offset) {
                    if (handle->arch->mapped(candidate + offset)
                        || global->queryFunction(Address(space, candidate + offset)) != nullptr) free = false;
                }
                if (!free) candidate -= size;
            }
            if (!free) throw LowlevelError("No address available for external function");
            target = candidate;
            handle->nextExternal = candidate - 1;
            nativeMutation = true;
            global->addFunction(Address(space, target), name);
            handle->externalSlots[target] = slot;
        }
        if (global->queryFunction(Address(space, target)) == nullptr)
            throw LowlevelError("Import target is not registered");
        nativeMutation = true;
        handle->imports[slot] = global->addExternalRef(Address(space, slot), Address(space, target), name);
    });
}

const char *rampage_decomp_prototype(void *h, uint64_t addr, uint8_t indirect, const char *text) noexcept {
    Handle *handle = static_cast<Handle *>(h);
    return mutate(handle, [&](bool &nativeMutation) {
        Address entry(handle->arch->getDefaultCodeSpace(), addr);
        Scope *global = handle->arch->symboltab->getGlobalScope();
        nativeMutation = indirect != 0;
        Funcdata *function = indirect != 0 ? global->queryExternalRefFunction(entry) : global->queryFunction(entry);
        if (function == nullptr) throw LowlevelError("Prototype target is not registered");
        PrototypePieces pieces;
        std::istringstream input(text);
        nativeMutation = true;
        parse_protopieces(pieces, input, handle->arch);
        handle->arch->clearAnalysis(function);
        function->getFuncProto().setPieces(pieces);
    });
}

// Marks a function, or the external function an import slot names, as never returning: the decompiler then ends
// control flow at calls to it.
const char *rampage_decomp_noreturn(void *h, uint64_t addr, uint8_t indirect) noexcept {
    Handle *handle = static_cast<Handle *>(h);
    return mutate(handle, [&](bool &nativeMutation) {
        Address entry(handle->arch->getDefaultCodeSpace(), addr);
        Scope *global = handle->arch->symboltab->getGlobalScope();
        Funcdata *function = indirect != 0 ? global->queryExternalRefFunction(entry) : global->queryFunction(entry);
        if (function == nullptr) throw LowlevelError("Noreturn target is not registered");
        nativeMutation = true;
        handle->arch->clearAnalysis(function);
        function->getFuncProto().setNoReturn(true);
    });
}

// Parses C declarations (typedefs, prototypes) into the program's type database, so matching functions get
const char *rampage_decomp_global(void *h, uint64_t addr, const char *text) noexcept {
    Handle *handle = static_cast<Handle *>(h);
    return mutate(handle, [&](bool &nativeMutation) {
        std::string name;
        std::string declaration(text);
        std::string word;
        for (size_t index = 0; index <= declaration.size(); ++index) {
            unsigned char character = index == declaration.size() ? 0 : declaration[index];
            if (std::isalnum(character) || character == '_') { word.push_back(character); continue; }
            if (word == "extern" || word == "typedef" || word == "static" || word == "volatile" || word == "const"
                || word == "auto" || word == "register" || word == "restrict")
                throw LowlevelError("Global qualifiers and storage classes are not supported");
            word.clear();
        }
        size_t last = declaration.find_last_not_of(" \t\r\n");
        if (last != std::string::npos && declaration[last] == ';') declaration.erase(last);
        std::istringstream input(declaration);
        nativeMutation = true;
        Datatype *type = parse_type(input, name, handle->arch);
        if (name.empty() || type->getMetatype() == TYPE_CODE || type->getSize() <= 0 || type->getSize() > 1048576)
            throw LowlevelError("Global requires a named, sized data declaration");
        Address address(handle->arch->getDefaultDataSpace(), addr);
        if (uintb(type->getSize() - 1) > address.getSpace()->getHighest() - addr)
            throw LowlevelError("Global declaration exceeds address space");
        if (!handle->arch->dataRange(addr, type->getSize()))
            throw LowlevelError("Global requires a fully mapped non-executable data range");
        Scope *scope = handle->arch->symboltab->getGlobalScope();
        std::vector<Symbol *> named;
        scope->queryByName(name, named);
        if (!named.empty()) throw LowlevelError("Global name is already registered");
        if (scope->findOverlap(address, type->getSize()) != nullptr)
            throw LowlevelError("Global declaration overlaps an existing symbol");
        SymbolEntry *entry = scope->addSymbol(name, type, address, Address());
        scope->setAttribute(entry->getSymbol(), Varnode::typelock | Varnode::namelock);
    });
}

// Parses C declarations (typedefs, prototypes) into the program's type database, so matching functions get
// signatures and their arguments are typed. Returns an error string on a parse failure, else null.
const char *rampage_decomp_parse_c(void *h, const char *text) noexcept {
    Handle *handle = static_cast<Handle *>(h);
    if (handle->poisoned) return "Decompiler handle is unavailable";
    if (handle->arch == nullptr || text == nullptr) return nullptr;
    return mutate(handle, [&](bool &nativeMutation) {
        std::istringstream in(text);
        nativeMutation = true;
        parse_C(handle->arch, in);
    });
}

const char *rampage_decomp_parse_type_library(void *h, const char *text, uint32_t packing,
                                            const char **json, size_t *length) noexcept {
    Handle *handle = static_cast<Handle *>(h);
    if (json == nullptr || length == nullptr || text == nullptr) return "Invalid type library input";
    *json = nullptr;
    *length = 0;
    const char *error = mutate(handle, [&](bool &nativeMutation) {
        nativeMutation = true;
        auto names = rampage::type_library::parse(handle->arch, text, packing, handle->typePacking);
        handle->typeResult = rampage::type_library::inventory(handle->arch, &names, handle->typePacking);
    });
    if (error != nullptr) {
        handle->poisoned = true;
        handle->tokens.clear();
        handle->results.clear();
        return error;
    }
    *json = handle->typeResult.c_str();
    *length = handle->typeResult.size();
    return nullptr;
}

const char *rampage_decomp_type_inventory(void *h, const char *name, const char **json, size_t *length) noexcept {
    Handle *handle = static_cast<Handle *>(h);
    if (json == nullptr || length == nullptr) return "Invalid type query output";
    *json = nullptr;
    *length = 0;
    if (handle == nullptr || handle->arch == nullptr || handle->poisoned) return "Decompiler handle is unavailable";
    try {
        std::vector<std::string> names;
        if (name != nullptr) names.emplace_back(name);
        handle->typeResult = rampage::type_library::inventory(handle->arch,
            name == nullptr ? nullptr : &names, handle->typePacking);
        *json = handle->typeResult.c_str();
        *length = handle->typeResult.size();
        return nullptr;
    } catch (const LowlevelError &error) {
        return setError(handle, error.explain.c_str());
    } catch (...) {
        return setError(handle, "Type inventory inspection failed");
    }
}

const char *rampage_decomp_local_variables(void *h, uint64_t function,
                                         const rampage::NativeLocalOverride *records, size_t count) noexcept {
    Handle *handle = static_cast<Handle *>(h);
    return mutate(handle, [&](bool &nativeMutation) {
        nativeMutation = true; // Parsing can intern types, even if the pending batch is refused.
        auto overrides = rampage::prepareLocals(handle->arch, records, count);
        if (count == 0) handle->localOverrides.erase(function);
        else handle->localOverrides[function] = std::move(overrides);
        handle->tokens.clear();
        handle->results.clear();
    });
}

const char *rampage_decomp_type_hints(void *h, uint64_t function,
                                    const rampage::NativeTypeHint *records, size_t count) noexcept {
    Handle *handle = static_cast<Handle *>(h);
    return mutate(handle, [&](bool &nativeMutation) {
        nativeMutation = true;
        auto hints = rampage::prepareTypeHints(handle->arch, records, count);
        if (count != 0 && handle->typeHints.count(function) == 0 && handle->typeHints.size() >= 32)
            throw LowlevelError("Native type hint functions exceed 32");
        if (count == 0) handle->typeHints.erase(function);
        else handle->typeHints[function] = std::move(hints);
        handle->calleeTypeShapes.clear();
        handle->tokens.clear();
        handle->results.clear();
    });
}

// Internal native regression bridge: no public Rust API or worker operation exposes this helper.
const char *rampage_decomp_test_hint_input_identity(void *h, uint64_t function) noexcept {
    Handle *handle = static_cast<Handle *>(h);
    return mutate(handle, [&](bool &nativeMutation) {
        nativeMutation = true;
        Funcdata *fd = handle->arch->symboltab->getGlobalScope()->queryFunction(
            Address(handle->arch->getDefaultCodeSpace(), function));
        if (fd == nullptr || !fd->isProcComplete() || fd->getFuncProto().numParams() == 0)
            throw LowlevelError("Native hint identity regression requires a recovered input");
        const auto *parameter = fd->getFuncProto().getParam(0);
        Varnode *input = fd->findVarnodeInput(parameter->getSize(), parameter->getAddress());
        Datatype *hint = handle->arch->types->findByName("HintState");
        if (input == nullptr || hint == nullptr)
            throw LowlevelError("Native hint identity regression setup is incomplete");
        hint = handle->arch->types->getTypePointer(input->getSize(), hint,
            handle->arch->getDefaultDataSpace()->getWordSize());
        try {
            // The selector intentionally has unrestricted use ranges. The later RDI definition has
            // the same storage and width but no symbol mapping: it must not inherit an input hint.
            rampage::TypeHintContext context{{}, nullptr};
            context.own.push_back({{input->getAddr(), input->getSize(), {}, "", hint}, false, true});
            fd->setInferenceHint(rampage::nativeInferenceHint, &context);
            bool identityPreserved = InferenceHintIdentityProbe::check(*fd, input, hint);
            fd->setInferenceHint(nullptr, nullptr);
            if (!identityPreserved)
                throw LowlevelError("Unmapped register reuse acquired an unrelated parameter hint");
        } catch (...) {
            fd->setInferenceHint(nullptr, nullptr);
            handle->arch->clearAnalysis(fd);
            throw;
        }
        handle->arch->clearAnalysis(fd);
        handle->tokens.clear();
        handle->results.clear();
    });
}

// Read-only: do not route assertion failures through the mutation/poisoning path. Publish no partial layout.
const char *rampage_decomp_inspect_layout(void *h, const char *name, size_t nameLength, PlainLayout *output) noexcept {
    Handle *handle = static_cast<Handle *>(h);
    if (handle == nullptr || handle->arch == nullptr || handle->poisoned) return "Decompiler handle is unavailable";
    if (output == nullptr || name == nullptr || !layoutIdentifier(name, nameLength))
        return "Invalid plain-struct layout input";
    try {
        PlainLayout result = inspectPlainLayout(handle->arch, string(name, nameLength));
        *output = result;
        handle->error.clear();
        handle->fallbackError = false;
        return nullptr;
    } catch (const LowlevelError &error) {
        if (error.explain.size() > 512 || std::any_of(error.explain.begin(), error.explain.end(),
            [](unsigned char ch) { return ch == 0 || ch > 127; }))
            return setError(handle, "Plain-struct layout inspection failed with an invalid native error");
        return setError(handle, error.explain.c_str());
    } catch (...) {
        return setError(handle, "Plain-struct layout inspection failed");
    }
}

const char *rampage_decomp_error(void *h) noexcept {
    return handleError(static_cast<Handle *>(h));
}

uint64_t rampage_decomp_import_target(void *h, uint64_t slot) noexcept {
    Handle *handle = static_cast<Handle *>(h);
    if (handle->arch == nullptr || handle->poisoned) return 0;
    auto found = handle->imports.find(slot);
    return found == handle->imports.end() ? 0 : found->second->getRefAddr().getOffset();
}

const char *rampage_decomp_assert_named_shape(void *h, const char *name) noexcept {
    Handle *handle = static_cast<Handle *>(h);
    if (handle == nullptr || handle->arch == nullptr || handle->poisoned)
        return "Decompiler handle is unavailable";
    try {
        Datatype *type = name == nullptr ? nullptr : handle->arch->types->findByName(name);
        if (type == nullptr) throw LowlevelError("Named assertion type does not exist");
        std::set<Datatype *> seen;
        rampage::type_library::assertCompleteGraph(type, seen);
        return nullptr;
    } catch (const LowlevelError &error) {
        return setError(handle, error.explain.c_str());
    } catch (...) {
        return setError(handle, "Named assertion native shape validation failed");
    }
}

const char *rampage_decomp_assert_type_model(void *h, const char *language,
        uint8_t pointerSize, uint8_t intSize, uint8_t longSize) noexcept {
    Handle *handle = static_cast<Handle *>(h);
    if (handle == nullptr || handle->arch == nullptr || handle->poisoned)
        return "Decompiler handle is unavailable";
    if (language == nullptr || handle->arch->selectedLanguage() != language
        || handle->arch->types->getSizeOfPointer() != pointerSize
        || handle->arch->types->getSizeOfInt() != intSize
        || handle->arch->types->getSizeOfLong() != longSize)
        return "Named type assertion target/compiler organization mismatch";
    return nullptr;
}

void rampage_decomp_data_organization(void *h, int32_t *pointerSize, int32_t *intSize, int32_t *longSize) noexcept {
    Handle *handle = static_cast<Handle *>(h);
    *pointerSize = *intSize = *longSize = 0;
    if (handle->arch == nullptr || handle->poisoned) return;
    *pointerSize = handle->arch->types->getSizeOfPointer();
    *intSize = handle->arch->types->getSizeOfInt();
    *longSize = handle->arch->types->getSizeOfLong();
}

const char *rampage_decomp_set_modes(void *h, size_t count, const uint64_t *addresses, const uint8_t *thumb) noexcept {
    Handle *handle = static_cast<Handle *>(h);
    return mutate(handle, [&](bool &nativeMutation) {
        for (size_t i = 0; i < count; ++i) {
            Address address(handle->arch->getDefaultCodeSpace(), addresses[i]);
            nativeMutation = true;
            handle->arch->context->setVariable("TMode", address, thumb[i] != 0 ? 1 : 0);
        }
    });
}

// Decompiles the function at `addr` to C. When `thumb` is set and the target has a TMode context variable
// (32-bit ARM), the function is decoded as Thumb. Returns a malloc'd string the caller frees, or null on failure.
char *rampage_decomp_function(void *h, uint64_t addr, const char *name, uint8_t thumb) noexcept {
    Handle *handle = static_cast<Handle *>(h);
    if (handle->arch == nullptr || handle->poisoned) return nullptr;
    Architecture *arch = handle->arch;
    Funcdata *fd = nullptr;
    std::vector<rampage::SavedLocal> savedLocals;
    rampage::TypeHintContext hintContext{{}, nullptr};
    hintContext.locals = &savedLocals;
    bool nativeMutation = false;
    handle->tokens.clear();
    handle->results.clear();
    try {
        Address entry(arch->getDefaultCodeSpace(), addr);
        if (arch->context != nullptr) {
            try {
                nativeMutation = true;
                arch->context->setVariable("TMode", entry, thumb != 0 ? 1 : 0);
            } catch (LowlevelError &) {
                // The target has no TMode variable; nothing to set.
            }
        }
        nativeMutation = true;
        handle->arch->resetTranslationCache();
        Scope *global = arch->symboltab->getGlobalScope();
        fd = global->queryFunction(entry);
        if (fd == nullptr) {
            string funcname = (name != nullptr && name[0] != '\0') ? name : "";
            if (funcname.empty()) arch->nameFunction(entry, funcname);
            fd = global->addFunction(entry, funcname)->getFunction();
        }
        fd->setInferenceHint(rampage::nativeInferenceHint, &hintContext);
        fd->setCallInferenceHint(rampage::nativeCallInferenceHint, &hintContext);
        arch->clearAnalysis(fd);
        // The entry is not a lower flow bound: cold blocks and tail targets can precede it.
        Address low(arch->getDefaultCodeSpace(), 0);
        Address high(arch->getDefaultCodeSpace(), arch->getDefaultCodeSpace()->getHighest());
        fd->followFlow(low, high);
        if (!handle->preparingTypeHintContext) {
            handle->calleeTypeShapes.clear();
            std::set<uintb> needed;
            size_t edges = 0;
            // Follow native directed CALL edges before applying any hint context or local overrides.
            for (int4 i = 0; i < fd->numCalls(); ++i) {
                const auto *call = fd->getCallSpecs(i);
                const auto *op = call->getOp();
                const auto &target = call->getEntryAddress();
                if (op == nullptr || op->code() != CPUI_CALL || target.isInvalid()
                    || target.getOffset() == addr) continue;
                bool hinted = handle->typeHints.count(target.getOffset()) != 0;
                const auto *callee = global->queryFunction(target);
                bool knownOutput = callee != nullptr && callee->getFuncProto().isOutputLocked();
                bool returnContext = !knownOutput && handle->arch->backedCode(target.getOffset())
                    && rampage::boundedRawReturnSuffix(fd, call);
                if (!hinted && !returnContext) continue;
                if (++edges > 256) throw LowlevelError("Native callee hint call edges exceed 256");
                needed.insert(target.getOffset());
                if (needed.size() > 32) throw LowlevelError("Native callee return context functions exceed 32");
            }
            if (!needed.empty()) {
                arch->clearAnalysis(fd);
                handle->preparingTypeHintContext = true;
                try {
                    for (uintb target : needed) {
                        uint8_t contextThumb = 0;
                        if (arch->context != nullptr) {
                            try {
                                contextThumb = arch->context->getVariable("TMode",
                                    Address(arch->getDefaultCodeSpace(), target)) != 0;
                            } catch (const LowlevelError &) {}
                        }
                        // This analyzes source bytes; it never executes the function being inspected.
                        char *contextText = rampage_decomp_function(h, target, nullptr, contextThumb);
                        if (contextText == nullptr) {
                            if (handle->typeHints.count(target) == 0 && !handle->poisoned && !handle->unsafeCleanup)
                                continue;
                            throw LowlevelError("Unsupported native callee hint context: " + handle->error);
                        }
                        free(contextText);
                    }
                } catch (...) {
                    handle->preparingTypeHintContext = false;
                    throw;
                }
                handle->preparingTypeHintContext = false;
                handle->tokens.clear();
                handle->results.clear();
                fd->followFlow(low, high);
            }
            hintContext.callees = &handle->calleeTypeShapes;
        }
        arch->allacts.getCurrent()->reset(*fd);
        arch->allacts.getCurrent()->perform(*fd);
        auto local = handle->localOverrides.find(addr);
        if (local != handle->localOverrides.end()) {
            rampage::applyLocals(fd, local->second, savedLocals);
            arch->clearAnalysis(fd);
            hintContext.edges = 0;
            fd->followFlow(low, high);
            arch->allacts.getCurrent()->reset(*fd);
            arch->allacts.getCurrent()->perform(*fd);
            rampage::verifyLocals(fd, local->second, savedLocals);
        }
        auto hints = handle->typeHints.find(addr);
        if (hints != handle->typeHints.end()) {
            hintContext.own = rampage::resolveTypeHints(fd, hints->second, savedLocals);
            if (!hintContext.own.empty()) {
                arch->clearAnalysis(fd);
                hintContext.edges = 0;
                fd->followFlow(low, high);
                arch->allacts.getCurrent()->reset(*fd);
                arch->allacts.getCurrent()->perform(*fd);
                rampage::verifyTypeHints(fd, hintContext.own, savedLocals);
                if (local != handle->localOverrides.end())
                    rampage::verifyLocals(fd, local->second, savedLocals);
            }
        }
        if (handle->preparingTypeHintContext) {
            const std::vector<rampage::TypeHint> empty;
            try {
                handle->calleeTypeShapes[addr] = rampage::collectCalleeTypeShape(fd,
                    hints == handle->typeHints.end() ? empty : hints->second, savedLocals);
            } catch (const LowlevelError &) {
                // Optional wrapper discovery is not a new admission rule for ordinary decompilation.
                // Explicitly requested hint contexts still refuse unsupported native shapes.
                if (hints != handle->typeHints.end()) throw;
            }
        }
        rampage::verifyCalleeTypeHints(fd, hintContext);
        fd->setInferenceHint(nullptr, nullptr);
        fd->setCallInferenceHint(nullptr, nullptr);
        LimitedOutput buffer;
        std::ostream out(&buffer);
        out.exceptions(std::ios::badbit | std::ios::failbit);
        DetachOutput detach{handle->emitter};
        arch->print->setOutputStream(&out);
        arch->print->docFunction(fd);
        arch->print->setOutputStream(nullptr);
        nativeMutation = false;
        rampage::collectFlow(fd, handle->tokens);
        nativeMutation = true;
        handle->results = rampage::collectResults(fd, handle->externalSlots, &savedLocals);
        nativeMutation = false;
        for (auto &token : handle->tokens) {
            if (!token.hasAddress || (token.kind != "call" && token.kind != "function")) continue;
            auto external = handle->externalSlots.find(token.address);
            if (external != handle->externalSlots.end()) token.address = external->second;
        }
        nativeMutation = true;
        rampage::restoreLocals(fd->getScopeLocal(), savedLocals);
        nativeMutation = false;
        const std::string &text = buffer.str();
        char *result = static_cast<char *>(malloc(text.size() + 1));
        if (result == nullptr) {
            failDecompilation(handle, fd, "Could not allocate decompiler output", false);
            return nullptr;
        }
        memcpy(result, text.c_str(), text.size() + 1);
        handle->error.clear();
        handle->fallbackError = false;
        return result;
    } catch (const LowlevelError &err) {
        if (fd != nullptr) fd->setInferenceHint(nullptr, nullptr);
        if (fd != nullptr) fd->setCallInferenceHint(nullptr, nullptr);
        try {
            if (fd != nullptr) rampage::restoreLocals(fd->getScopeLocal(), savedLocals);
        } catch (...) {
            handle->unsafeCleanup = true;
        }
        failDecompilation(handle, fd, err.explain.c_str(), true);
        return nullptr;
    } catch (const DecoderError &error) {
        if (fd != nullptr) fd->setInferenceHint(nullptr, nullptr);
        if (fd != nullptr) fd->setCallInferenceHint(nullptr, nullptr);
        handle->unsafeCleanup |= nativeMutation;
        failDecompilation(handle, fd, error.explain.c_str(), false);
        return nullptr;
    } catch (const std::exception &error) {
        if (fd != nullptr) fd->setInferenceHint(nullptr, nullptr);
        if (fd != nullptr) fd->setCallInferenceHint(nullptr, nullptr);
        handle->unsafeCleanup |= nativeMutation;
        failDecompilation(handle, fd, error.what(), false);
        return nullptr;
    } catch (...) {
        if (fd != nullptr) fd->setInferenceHint(nullptr, nullptr);
        if (fd != nullptr) fd->setCallInferenceHint(nullptr, nullptr);
        handle->unsafeCleanup |= nativeMutation;
        failDecompilation(handle, fd, "Unexpected native decompiler exception", false);
        return nullptr;
    }
}

size_t rampage_decomp_token_count(void *h) noexcept { return static_cast<Handle *>(h)->tokens.size(); }

const char *rampage_decomp_results(void *h) noexcept {
    const auto &results = static_cast<Handle *>(h)->results;
    return results.empty() ? nullptr : results.c_str();
}

const char *rampage_decomp_token(void *h, size_t index, const char **kind, uint64_t *address,
                               uint8_t *hasAddress) noexcept {
    const auto &tokens = static_cast<Handle *>(h)->tokens;
    *kind = nullptr; *address = 0; *hasAddress = 0;
    if (index >= tokens.size()) return nullptr;
    const auto &token = tokens[index];
    *kind = token.kind.c_str(); *address = token.address; *hasAddress = token.hasAddress ? 1 : 0;
    return token.text.c_str();
}

uint8_t rampage_decomp_token_span(void *h, size_t index, size_t *start, size_t *end) noexcept {
    if (start == nullptr || end == nullptr) return 0;
    *start = *end = 0;
    const auto &tokens = static_cast<Handle *>(h)->tokens;
    if (index >= tokens.size() || !tokens[index].hasSpan) return 0;
    *start = tokens[index].start;
    *end = tokens[index].end;
    return 1;
}

void rampage_decomp_free_string(char *s) noexcept { free(s); }

void rampage_decomp_close(void *h) noexcept {
    Handle *handle = static_cast<Handle *>(h);
    if (handle == nullptr) return;
    // Unexpected exceptions can leave native ownership dangling; retain its borrowed token storage too.
    if (handle->unsafeCleanup) return;
    DeleteArchitecture()(handle->arch);
    try { delete handle; } catch (...) {}
}

} // extern "C"
