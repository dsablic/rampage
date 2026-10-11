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

    void resetTranslationCache() {
        const_cast<Sleigh *>(static_cast<const Sleigh *>(translate))->clearCache();
    }

    bool mapped(uintb address) const { return image->mapped(address); }

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
    std::string error;
    uintb nextExternal = 0;
    std::map<uintb, ExternRefSymbol *> imports;
    std::map<uintb, uintb> externalSlots;
    std::vector<rampage::Token> tokens;
    bool poisoned = false;
    bool fallbackError = false;
};

void failDecompilation(Handle *handle, Funcdata *function, const char *message) noexcept {
    handle->poisoned = true;
    handle->fallbackError = true;
    try { handle->error = message; handle->fallbackError = false; } catch (...) {}
    handle->tokens.clear();
    try {
        handle->arch->print->clear();
        handle->arch->print->setOutputStream(nullptr);
        if (function != nullptr) handle->arch->clearAnalysis(function);
        handle->poisoned = false;
    } catch (...) {}
}

class LimitedOutput : public std::streambuf {
    std::string data;
protected:
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

} // namespace

extern "C" {

// Opens a decompiler over the given segments. `langid` is Ghidra's 5-part id, e.g. "x86:LE:64:default:gcc".
// Returns a handle even on failure; rampage_decomp_error reports what went wrong.
void *rampage_decomp_open(const char *sleighhome, const char *langid, size_t nseg, const uint64_t *bases,
                          const uint8_t *const *ptrs, const size_t *lens, const uint64_t *sizes,
                          const uint8_t *readable, const uint8_t *executable, const uint8_t *writable) {
    static bool started = false;
    if (!started) {
        startDecompilerLibrary(sleighhome);
        started = true;
    }
    Handle *handle = new Handle();
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
    // Built directly (not through the "raw" capability, which would open a file) so the image is ours.
    MemArchitecture *arch = new MemArchitecture(langid, new MemImage(std::move(segments)), &std::cerr);
    try {
        DocumentStorage store;
        arch->init(store);
        handle->arch = arch;
        arch->print->setEmitter(new rampage::TokenEmitter(handle->tokens));
        handle->nextExternal = arch->getDefaultCodeSpace()->getHighest();
    } catch (LowlevelError &err) {
        handle->error = err.explain;
        delete arch; // frees the image too, whether or not init handed it over
    } catch (DecoderError &err) {
        handle->error = err.explain;
        delete arch;
    }
    return handle;
}

// Registers a known function address with a name, so calls to it render by name rather than by address. Must be
// called before decompiling callers. Ignored on failure (e.g. an address outside any space).
void rampage_decomp_add_symbol(void *h, uint64_t addr, const char *name) {
    Handle *handle = static_cast<Handle *>(h);
    if (handle->arch == nullptr || handle->poisoned || name == nullptr || name[0] == '\0') return;
    try {
        Architecture *arch = handle->arch;
        Address entry(arch->getDefaultCodeSpace(), addr);
        Scope *global = arch->symboltab->getGlobalScope();
        if (global->queryFunction(entry) == nullptr) {
            global->addFunction(entry, name);
        }
    } catch (LowlevelError &) {
        // A bad address is not fatal; the symbol is simply not added.
    }
}

const char *rampage_decomp_symbol(void *h, uint64_t addr, const char *name) {
    Handle *handle = static_cast<Handle *>(h);
    if (handle->poisoned) return "Decompiler handle is unavailable";
    try {
        Address entry(handle->arch->getDefaultCodeSpace(), addr);
        Scope *global = handle->arch->symboltab->getGlobalScope();
        Funcdata *function = global->queryFunction(entry);
        if (function == nullptr) global->addFunction(entry, name);
        else {
            global->renameSymbol(function->getSymbol(), name);
            function->setDisplayName(name);
        }
        handle->error.clear();
        return nullptr;
    } catch (LowlevelError &error) {
        handle->error = error.explain;
        return handle->error.c_str();
    }
}

const char *rampage_decomp_import(void *h, uint64_t slot, uint64_t target, uint8_t hasTarget, const char *name) {
    Handle *handle = static_cast<Handle *>(h);
    if (handle->poisoned) return "Decompiler handle is unavailable";
    try {
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
            global->addFunction(Address(space, target), name);
            handle->externalSlots[target] = slot;
        }
        if (global->queryFunction(Address(space, target)) == nullptr)
            throw LowlevelError("Import target is not registered");
        handle->imports[slot] = global->addExternalRef(Address(space, slot), Address(space, target), name);
        handle->error.clear();
        return nullptr;
    } catch (LowlevelError &error) {
        handle->error = error.explain;
        return handle->error.c_str();
    }
}

const char *rampage_decomp_prototype(void *h, uint64_t addr, uint8_t indirect, const char *text) {
    Handle *handle = static_cast<Handle *>(h);
    if (handle->poisoned) return "Decompiler handle is unavailable";
    try {
        Address entry(handle->arch->getDefaultCodeSpace(), addr);
        Scope *global = handle->arch->symboltab->getGlobalScope();
        Funcdata *function = indirect != 0 ? global->queryExternalRefFunction(entry) : global->queryFunction(entry);
        if (function == nullptr) throw LowlevelError("Prototype target is not registered");
        PrototypePieces pieces;
        std::istringstream input(text);
        parse_protopieces(pieces, input, handle->arch);
        handle->arch->clearAnalysis(function);
        function->getFuncProto().setPieces(pieces);
        handle->error.clear();
        return nullptr;
    } catch (LowlevelError &error) {
        handle->error = error.explain;
        return handle->error.c_str();
    } catch (ParseError &error) {
        handle->error = error.explain;
        return handle->error.c_str();
    }
}

// Parses C declarations (typedefs, prototypes) into the program's type database, so matching functions get
// signatures and their arguments are typed. Returns an error string on a parse failure, else null.
const char *rampage_decomp_parse_c(void *h, const char *text) {
    Handle *handle = static_cast<Handle *>(h);
    if (handle->poisoned) return "Decompiler handle is unavailable";
    if (handle->arch == nullptr || text == nullptr) return nullptr;
    try {
        std::istringstream in(text);
        parse_C(handle->arch, in);
        handle->error.clear();
        return nullptr;
    } catch (ParseError &err) {
        handle->error = err.explain;
        return handle->error.c_str();
    } catch (LowlevelError &err) {
        handle->error = err.explain;
        return handle->error.c_str();
    }
}

const char *rampage_decomp_error(void *h) {
    Handle *handle = static_cast<Handle *>(h);
    if (handle->fallbackError) return "Native decompiler failed; handle is unavailable";
    return handle->error.empty() ? nullptr : handle->error.c_str();
}

uint64_t rampage_decomp_import_target(void *h, uint64_t slot) {
    Handle *handle = static_cast<Handle *>(h);
    auto found = handle->imports.find(slot);
    return found == handle->imports.end() ? 0 : found->second->getRefAddr().getOffset();
}

void rampage_decomp_data_organization(void *h, int32_t *pointerSize, int32_t *intSize, int32_t *longSize) {
    Handle *handle = static_cast<Handle *>(h);
    *pointerSize = handle->arch->types->getSizeOfPointer();
    *intSize = handle->arch->types->getSizeOfInt();
    *longSize = handle->arch->types->getSizeOfLong();
}

const char *rampage_decomp_set_modes(void *h, size_t count, const uint64_t *addresses, const uint8_t *thumb) {
    Handle *handle = static_cast<Handle *>(h);
    if (handle->poisoned) return "Decompiler handle is unavailable";
    try {
        for (size_t i = 0; i < count; ++i) {
            Address address(handle->arch->getDefaultCodeSpace(), addresses[i]);
            handle->arch->context->setVariable("TMode", address, thumb[i] != 0 ? 1 : 0);
        }
        handle->error.clear();
        return nullptr;
    } catch (LowlevelError &error) {
        handle->error = error.explain;
        return handle->error.c_str();
    }
}

// Decompiles the function at `addr` to C. When `thumb` is set and the target has a TMode context variable
// (32-bit ARM), the function is decoded as Thumb. Returns a malloc'd string the caller frees, or null on failure.
char *rampage_decomp_function(void *h, uint64_t addr, const char *name, uint8_t thumb) {
    Handle *handle = static_cast<Handle *>(h);
    if (handle->arch == nullptr || handle->poisoned) return nullptr;
    Architecture *arch = handle->arch;
    Funcdata *fd = nullptr;
    handle->tokens.clear();
    try {
        Address entry(arch->getDefaultCodeSpace(), addr);
        if (arch->context != nullptr) {
            try {
                arch->context->setVariable("TMode", entry, thumb != 0 ? 1 : 0);
            } catch (LowlevelError &) {
                // The target has no TMode variable; nothing to set.
            }
        }
        handle->arch->resetTranslationCache();
        Scope *global = arch->symboltab->getGlobalScope();
        fd = global->queryFunction(entry);
        if (fd == nullptr) {
            string funcname = (name != nullptr && name[0] != '\0') ? name : "";
            if (funcname.empty()) arch->nameFunction(entry, funcname);
            fd = global->addFunction(entry, funcname)->getFunction();
        }
        arch->clearAnalysis(fd);
        Address high(arch->getDefaultCodeSpace(), arch->getDefaultCodeSpace()->getHighest());
        fd->followFlow(entry, high);
        arch->allacts.getCurrent()->reset(*fd);
        arch->allacts.getCurrent()->perform(*fd);
        LimitedOutput buffer;
        std::ostream out(&buffer);
        out.exceptions(std::ios::badbit | std::ios::failbit);
        arch->print->setOutputStream(&out);
        arch->print->docFunction(fd);
        rampage::collectFlow(fd, handle->tokens);
        for (auto &token : handle->tokens) {
            if (!token.hasAddress || (token.kind != "call" && token.kind != "function")) continue;
            auto external = handle->externalSlots.find(token.address);
            if (external != handle->externalSlots.end()) token.address = external->second;
        }
        const std::string &text = buffer.str();
        char *result = static_cast<char *>(malloc(text.size() + 1));
        if (result != nullptr) memcpy(result, text.c_str(), text.size() + 1);
        return result;
    } catch (LowlevelError &err) {
        failDecompilation(handle, fd, err.explain.c_str());
        return nullptr;
    } catch (std::exception &error) {
        failDecompilation(handle, fd, error.what());
        return nullptr;
    } catch (...) {
        failDecompilation(handle, fd, "Unexpected native decompiler exception");
        return nullptr;
    }
}

size_t rampage_decomp_token_count(void *h) { return static_cast<Handle *>(h)->tokens.size(); }

const char *rampage_decomp_token(void *h, size_t index, const char **kind, uint64_t *address, uint8_t *hasAddress) {
    const auto &token = static_cast<Handle *>(h)->tokens.at(index);
    *kind = token.kind.c_str(); *address = token.address; *hasAddress = token.hasAddress ? 1 : 0;
    return token.text.c_str();
}

void rampage_decomp_free_string(char *s) { free(s); }

void rampage_decomp_close(void *h) {
    Handle *handle = static_cast<Handle *>(h);
    delete handle->arch; // deletes the loader (our MemImage) too
    delete handle;
}

} // extern "C"
