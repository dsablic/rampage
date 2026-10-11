// A C ABI over Ghidra's decompiler library. One handle holds a SleighArchitecture with an in-memory image
// spanning the loaded program's executable segments, so many functions decompile from a single setup.

#include "libdecomp.hh"
#include "sleigh_arch.hh"
#include "loadimage.hh"
#include "funcdata.hh"
#include "printc.hh"

#include <cstring>
#include <sstream>
#include <vector>

using namespace ghidra;

namespace {

// A segment of program bytes placed at a virtual address.
struct Segment {
    uintb base;
    std::vector<uint1> bytes;
};

// An image backed by memory segments rather than a file; unmapped addresses read as zero.
class MemImage : public LoadImage {
    std::vector<Segment> segments;
    AddrSpace *spaceid = nullptr;

public:
    MemImage(std::vector<Segment> segs) : LoadImage("memory"), segments(std::move(segs)) {}

    void attachToSpace(AddrSpace *id) { spaceid = id; }

    void loadFill(uint1 *ptr, int4 size, const Address &addr) override {
        uintb start = addr.getOffset();
        for (int4 i = 0; i < size; ++i) {
            uintb at = start + i;
            uint1 value = 0;
            for (const Segment &seg : segments) {
                if (at >= seg.base && at < seg.base + seg.bytes.size()) {
                    value = seg.bytes[at - seg.base];
                    break;
                }
            }
            ptr[i] = value;
        }
    }

    string getArchType(void) const override { return "memory"; }
    void adjustVma(long adjust) override {}
};

// Mirrors RawBinaryArchitecture, but takes its bytes from a MemImage we own until init hands it over.
class MemArchitecture : public SleighArchitecture {
    MemImage *image;

    void buildLoader(DocumentStorage &store) override {
        collectSpecFiles(*errorstream);
        loader = image;
    }
    void resolveArchitecture(void) override {
        archid = getTarget();
        SleighArchitecture::resolveArchitecture();
    }
    void postSpecFile(void) override {
        Architecture::postSpecFile();
        image->attachToSpace(getDefaultCodeSpace());
    }

public:
    MemArchitecture(const string &target, MemImage *img, ostream *estream)
        : SleighArchitecture("memory", target, estream), image(img) {}
};

struct Handle {
    Architecture *arch = nullptr;
    std::string error;
};

} // namespace

extern "C" {

// Opens a decompiler over the given segments. `langid` is Ghidra's 5-part id, e.g. "x86:LE:64:default:gcc".
// Returns a handle even on failure; rampage_decomp_error reports what went wrong.
void *rampage_decomp_open(const char *sleighhome, const char *langid, size_t nseg, const uint64_t *bases,
                          const uint8_t *const *ptrs, const size_t *lens) {
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
        seg.bytes.assign(ptrs[i], ptrs[i] + lens[i]);
        segments.push_back(std::move(seg));
    }
    MemImage *image = new MemImage(std::move(segments));
    try {
        ArchitectureCapability *capa = ArchitectureCapability::getCapability("raw");
        // Build directly so the image is ours; the raw capability would open a file instead.
        MemArchitecture *arch = new MemArchitecture(langid, image, &std::cerr);
        DocumentStorage store;
        arch->init(store);
        handle->arch = arch;
        (void)capa;
    } catch (LowlevelError &err) {
        delete image;
        handle->error = err.explain;
    } catch (DecoderError &err) {
        delete image;
        handle->error = err.explain;
    }
    return handle;
}

const char *rampage_decomp_error(void *h) {
    Handle *handle = static_cast<Handle *>(h);
    return handle->error.empty() ? nullptr : handle->error.c_str();
}

// Decompiles the function at `addr` to C. Returns a malloc'd string the caller frees, or null on failure.
char *rampage_decomp_function(void *h, uint64_t addr, const char *name) {
    Handle *handle = static_cast<Handle *>(h);
    if (handle->arch == nullptr) return nullptr;
    Architecture *arch = handle->arch;
    try {
        Address entry(arch->getDefaultCodeSpace(), addr);
        Scope *global = arch->symboltab->getGlobalScope();
        Funcdata *fd = global->queryFunction(entry);
        if (fd == nullptr) {
            string funcname = (name != nullptr && name[0] != '\0') ? name : "";
            if (funcname.empty()) arch->nameFunction(entry, funcname);
            fd = global->addFunction(entry, funcname)->getFunction();
        }
        if (fd->isProcStarted()) arch->clearAnalysis(fd);
        Address high(arch->getDefaultCodeSpace(), arch->getDefaultCodeSpace()->getHighest());
        fd->followFlow(entry, high);
        arch->allacts.getCurrent()->reset(*fd);
        arch->allacts.getCurrent()->perform(*fd);
        std::ostringstream out;
        arch->print->setOutputStream(&out);
        arch->print->docFunction(fd);
        std::string text = out.str();
        char *result = static_cast<char *>(malloc(text.size() + 1));
        if (result != nullptr) memcpy(result, text.c_str(), text.size() + 1);
        return result;
    } catch (LowlevelError &err) {
        handle->error = err.explain;
        return nullptr;
    }
}

void rampage_decomp_free_string(char *s) { free(s); }

void rampage_decomp_close(void *h) {
    Handle *handle = static_cast<Handle *>(h);
    delete handle->arch; // deletes the loader (our MemImage) too
    delete handle;
}

} // extern "C"
