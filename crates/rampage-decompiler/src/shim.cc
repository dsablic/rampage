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

    void resetTranslationCache() {
        const_cast<Sleigh *>(static_cast<const Sleigh *>(translate))->clearCache();
    }

    bool mapped(uintb address) const { return image->mapped(address); }
    bool dataRange(uintb address, uintb size) const { return image->dataRange(address, size); }

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
    bool poisoned = false;
    bool fallbackError = false;
    bool unsafeCleanup = false;
};

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

} // namespace

extern "C" {

// Opens a decompiler over the given segments. `langid` is Ghidra's 5-part id, e.g. "x86:LE:64:default:gcc".
// Returns an error handle on failure, or null if the handle itself could not be allocated.
void *rampage_decomp_open(const char *sleighhome, const char *langid, size_t nseg, const uint64_t *bases,
                          const uint8_t *const *ptrs, const size_t *lens, const uint64_t *sizes,
                          const uint8_t *readable, const uint8_t *executable, const uint8_t *writable) noexcept {
    static bool started = false;
    static bool startupFailed = false;
    std::unique_ptr<Handle> handle;
    std::unique_ptr<MemArchitecture, DeleteArchitecture> arch;
    bool initializing = false;
    try {
        handle.reset(new Handle());
        if (startupFailed) {
            setError(handle.get(), "Decompiler library initialization failed; restart required", true);
            return handle.release();
        }
        if (!started) {
            // Failed initialization may leave process-global registries partially populated.
            startupFailed = true;
            startDecompilerLibrary(sleighhome);
            started = true;
            startupFailed = false;
        }
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

const char *rampage_decomp_error(void *h) noexcept {
    return handleError(static_cast<Handle *>(h));
}

uint64_t rampage_decomp_import_target(void *h, uint64_t slot) noexcept {
    Handle *handle = static_cast<Handle *>(h);
    if (handle->arch == nullptr || handle->poisoned) return 0;
    auto found = handle->imports.find(slot);
    return found == handle->imports.end() ? 0 : found->second->getRefAddr().getOffset();
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
        arch->clearAnalysis(fd);
        Address high(arch->getDefaultCodeSpace(), arch->getDefaultCodeSpace()->getHighest());
        fd->followFlow(entry, high);
        arch->allacts.getCurrent()->reset(*fd);
        arch->allacts.getCurrent()->perform(*fd);
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
        handle->results = rampage::collectResults(fd, handle->externalSlots);
        nativeMutation = false;
        for (auto &token : handle->tokens) {
            if (!token.hasAddress || (token.kind != "call" && token.kind != "function")) continue;
            auto external = handle->externalSlots.find(token.address);
            if (external != handle->externalSlots.end()) token.address = external->second;
        }
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
        failDecompilation(handle, fd, err.explain.c_str(), true);
        return nullptr;
    } catch (const DecoderError &error) {
        handle->unsafeCleanup |= nativeMutation;
        failDecompilation(handle, fd, error.explain.c_str(), false);
        return nullptr;
    } catch (const std::exception &error) {
        handle->unsafeCleanup |= nativeMutation;
        failDecompilation(handle, fd, error.what(), false);
        return nullptr;
    } catch (...) {
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
