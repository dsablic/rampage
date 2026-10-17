#pragma once

#include "funcdata.hh"
#include "architecture.hh"
#include "database.hh"
#include "op.hh"
#include "type.hh"
#include "translate.hh"
#include "comment.hh"
#include "variable.hh"
#include "local_variables.hh"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <ostream>
#include <set>
#include <streambuf>
#include <string>
#include <utility>

namespace rampage {
namespace results_detail {

constexpr size_t maxResultBytes = 4 * 1024 * 1024;
constexpr size_t maxResultItems = 262144;

class Json {
    std::string data;
public:
    void append(const char *text, size_t size) {
        if (size > maxResultBytes - data.size())
            throw ghidra::LowlevelError("Decompiler structured result byte limit exceeded");
        data.append(text, size);
    }
    void append(const char *text) { append(text, std::strlen(text)); }
    void number(uint64_t value) {
        std::string text = std::to_string(value);
        append(text.data(), text.size());
    }
    void boolean(bool value) { append(value ? "true" : "false"); }
    void quote(const std::string &text) {
        static const char hex[] = "0123456789abcdef";
        append("\"");
        for (size_t i = 0; i < text.size();) {
            unsigned char character = static_cast<unsigned char>(text[i]);
            if (character == '"' || character == '\\') {
                char escaped[] = {'\\', static_cast<char>(character)};
                append(escaped, sizeof(escaped));
                ++i;
            } else if (character < 0x20) {
                char escaped[] = {'\\', 'u', '0', '0', hex[character >> 4], hex[character & 15]};
                append(escaped, sizeof(escaped));
                ++i;
            } else if (character < 0x80) {
                append(text.data() + i++, 1);
            } else {
                size_t length = character >= 0xc2 && character <= 0xdf ? 2
                    : character >= 0xe0 && character <= 0xef ? 3
                    : character >= 0xf0 && character <= 0xf4 ? 4 : 0;
                bool valid = length != 0 && length <= text.size() - i;
                for (size_t j = 1; valid && j < length; ++j) {
                    unsigned char next = static_cast<unsigned char>(text[i + j]);
                    valid = next >= 0x80 && next <= 0xbf;
                }
                if (valid) {
                    unsigned char next = static_cast<unsigned char>(text[i + 1]);
                    valid = !(character == 0xe0 && next < 0xa0)
                        && !(character == 0xed && next >= 0xa0)
                        && !(character == 0xf0 && next < 0x90)
                        && !(character == 0xf4 && next >= 0x90);
                }
                if (valid) {
                    append(text.data() + i, length);
                    i += length;
                } else {
                    append("\\ufffd");
                    ++i;
                }
            }
        }
        append("\"");
    }
    void address(const ghidra::Address &address) {
        if (address.isInvalid()) append("null");
        else number(address.getOffset());
    }
    std::string take() { return std::move(data); }
};

class TypeOutput : public std::streambuf {
    std::string data;
protected:
    int_type overflow(int_type character) override {
        if (traits_type::eq_int_type(character, traits_type::eof())) return traits_type::not_eof(character);
        if (data.size() >= maxResultBytes)
            throw ghidra::LowlevelError("Decompiler structured type byte limit exceeded");
        data.push_back(traits_type::to_char_type(character));
        return character;
    }
    std::streamsize xsputn(const char *text, std::streamsize count) override {
        if (count < 0 || uint64_t(count) > maxResultBytes - data.size())
            throw ghidra::LowlevelError("Decompiler structured type byte limit exceeded");
        data.append(text, size_t(count));
        return count;
    }
public:
    const std::string &str() const { return data; }
};

inline void countItem(size_t &count) {
    if (count >= maxResultItems) throw ghidra::LowlevelError("Decompiler structured result item limit exceeded");
    ++count;
}

inline uint64_t nonnegative(ghidra::int4 value) {
    if (value < 0) throw ghidra::LowlevelError("Invalid negative size or index in structured result");
    return uint64_t(value);
}

inline void emitType(Json &json, const ghidra::Datatype *type) {
    json.append("{\"name\":");
    if (type == nullptr) json.quote("");
    else if (!type->getDisplayName().empty()) json.quote(type->getDisplayName());
    else {
        TypeOutput output;
        std::ostream stream(&output);
        stream.exceptions(std::ios::badbit | std::ios::failbit);
        type->printRaw(stream);
        json.quote(output.str());
    }
    json.append(",\"size\":");
    json.number(type == nullptr ? 0 : nonnegative(type->getSize()));
    json.append("}");
}

inline const char *storageKind(const ghidra::Address &address, bool dynamic) {
    if (dynamic) return "dynamic";
    if (address.isInvalid()) return "unknown";
    switch (address.getSpace()->getType()) {
        case ghidra::IPTR_PROCESSOR: return "processor";
        case ghidra::IPTR_SPACEBASE: return "spacebase";
        case ghidra::IPTR_INTERNAL: return "internal";
        case ghidra::IPTR_JOIN: return "join";
        case ghidra::IPTR_CONSTANT: return "constant";
        case ghidra::IPTR_FSPEC: return "fspec";
        case ghidra::IPTR_IOP: return "iop";
    }
    return "unknown";
}

inline void emitStorage(Json &json, const ghidra::Address &address, ghidra::int4 size, size_t &count,
                        const ghidra::SymbolEntry *entry = nullptr) {
    bool dynamic = entry != nullptr && entry->isDynamic();
    json.append("{\"kind\":");
    json.quote(storageKind(address, dynamic));
    json.append(",\"space\":");
    if (address.isInvalid()) json.append("null");
    else json.quote(address.getSpace()->getName());
    json.append(",\"address\":");
    json.address(address);
    if (!address.isInvalid()) {
        json.append(",\"address_size_bytes\":");
        json.number(address.getSpace()->getAddrSize());
    }
    json.append(",\"size\":");
    json.number(nonnegative(size));
    json.append(",\"use_ranges\":");
    if (entry == nullptr) json.append("null");
    else {
        json.append("[");
        const auto &ranges = entry->getUseLimit();
        for (auto range = ranges.begin(); range != ranges.end(); ++range) {
            countItem(count);
            if (range != ranges.begin()) json.append(",");
            json.append("{\"space\":");
            json.quote(range->getSpace()->getName());
            json.append(",\"start\":");
            json.number(range->getFirst());
            json.append(",\"end\":");
            json.number(range->getLast());
            json.append("}");
        }
        json.append("]");
    }
    json.append(",\"dynamic_hash\":");
    if (dynamic) json.number(entry->getHash());
    else json.append("null");
    json.append(",\"symbol_offset\":");
    if (entry != nullptr) json.number(nonnegative(entry->getOffset()));
    else json.append("null");
    json.append(",\"is_piece\":");
    if (entry != nullptr) json.boolean(entry->isPiece());
    else json.append("null");
    const ghidra::JoinRecord *join = !address.isInvalid() && address.isJoin()
        ? address.getSpace()->getManager()->findJoin(address.getOffset()) : nullptr;
    json.append(",\"join_logical_size\":");
    if (join != nullptr) json.number(nonnegative(join->getUnified().size));
    else json.append("null");
    json.append(",\"pieces\":[");
    if (join != nullptr) {
        uint64_t logicalOffset = 0;
        for (ghidra::int4 j = 0; j < join->numPieces(); ++j) {
            countItem(count);
            if (j != 0) json.append(",");
            ghidra::int4 i = address.isBigEndian() ? j : join->numPieces() - 1 - j;
            const auto &piece = join->getPiece(i);
            json.append("{\"kind\":");
            json.quote(storageKind(piece.getAddr(), false));
            json.append(",\"space\":");
            json.quote(piece.space->getName());
            json.append(",\"address\":");
            json.number(piece.offset);
            json.append(",\"address_size_bytes\":");
            json.number(piece.space->getAddrSize());
            json.append(",\"size\":");
            json.number(nonnegative(piece.size));
            json.append(",\"logical_offset\":");
            json.number(logicalOffset);
            json.append("}");
            logicalOffset += nonnegative(piece.size);
        }
    }
    json.append("]");
    json.append("}");
}

inline void emitVariable(Json &json, const ghidra::Symbol *symbol, size_t &count) {
    json.append("{\"name\":");
    json.quote(symbol->getDisplayName());
    json.append(",\"data_type\":");
    emitType(json, symbol->getType());
    json.append(",\"kind\":");
    json.quote(symbol->getCategory() == ghidra::Symbol::function_parameter ? "parameter" : "local");
    json.append(",\"storage\":[");
    for (ghidra::int4 i = 0; i < symbol->numEntries(); ++i) {
        countItem(count);
        if (i != 0) json.append(",");
        const ghidra::SymbolEntry *entry = symbol->getMapEntry(i);
        emitStorage(json, entry->getAddr(), entry->getSize(), count, entry);
    }
    json.append("]}");
}

inline bool isVariable(const ghidra::Symbol *symbol) {
    return (symbol->getCategory() == ghidra::Symbol::no_category
        || symbol->getCategory() == ghidra::Symbol::function_parameter)
        && !symbol->isHiddenReturn() && !symbol->isIndirectStorage();
}

inline const ghidra::Varnode *copySource(const ghidra::Varnode *value) {
    for (size_t depth = 0; value != nullptr && depth <= 16; ++depth) {
        const auto *op = value->getDef();
        if (op == nullptr || (op->code() != ghidra::CPUI_COPY && op->code() != ghidra::CPUI_CAST))
            return value;
        if (depth == 16 || op->numInput() != 1 || op->getIn(0)->getSize() != value->getSize()) return nullptr;
        value = op->getIn(0);
    }
    return nullptr;
}

inline bool directReturn(const ghidra::Funcdata *function, const ghidra::Varnode *output) {
    if (output == nullptr) return false;
    bool found = false;
    size_t visited = 0;
    for (auto iter = function->beginOp(ghidra::CPUI_RETURN);
         iter != function->endOp(ghidra::CPUI_RETURN); ++iter) {
        if (++visited > 256) return false;
        const auto *op = *iter;
        if (op->isDead() || op->getHaltType() != 0) continue;
        if (op->numInput() != 2) return false;
        const auto *value = op->getIn(1);
        bool matches = false;
        for (size_t depth = 0; depth <= 16; ++depth) {
            if (value == output) { matches = true; break; }
            const auto *definition = value->getDef();
            if (depth == 16 || definition == nullptr || definition->numInput() != 1
                || (definition->code() != ghidra::CPUI_COPY && definition->code() != ghidra::CPUI_CAST)
                || definition->getIn(0)->getSize() != value->getSize()) break;
            value = definition->getIn(0);
        }
        if (!matches) return false;
        found = true;
    }
    return found;
}

inline bool wholeMapping(const ghidra::Symbol *symbol, const ghidra::SymbolEntry *entry) {
    if (symbol == nullptr || entry == nullptr || symbol->numEntries() != 1 || entry->isDynamic()
        || entry->getAddr().isInvalid() || entry->isPiece() || entry->getOffset() != 0
        || entry->getSize() != symbol->getType()->getSize()
        || entry->getSize() <= 0 || entry->getSize() > 1048576 || entry->getUseLimit().numRanges() > 256
        || entry->getAddr().getSpace()->getName().empty() || entry->getAddr().getSpace()->getName().size() > 128
        || symbol->isIndirectStorage() || symbol->isHiddenReturn()) return false;
    auto kind = entry->getAddr().getSpace()->getType();
    return kind == ghidra::IPTR_PROCESSOR || kind == ghidra::IPTR_SPACEBASE;
}

inline void emitCallValue(Json &json, ghidra::Funcdata *function, const ghidra::Varnode *value, size_t &count,
                           const std::vector<SavedLocal> *saved) {
    const ghidra::Symbol *symbol = nullptr;
    const ghidra::SymbolEntry *entry = nullptr;
    const ghidra::Varnode *source = value == nullptr ? nullptr : copySource(value);
    bool complete = false;
    bool computed = source != nullptr && source->isWritten()
        && source->getDef()->code() != ghidra::CPUI_CALL && source->getDef()->code() != ghidra::CPUI_CALLIND;
    // Computed expressions and partial/split aliases never acquire a storage identity through spelling.
    if (source != nullptr && !source->isConstant()) {
        const auto *high = source->getHigh();
        if (high != nullptr) {
            symbol = high->getSymbol();
            entry = high->getSymbolEntry();
            complete = !computed && wholeMapping(symbol, entry) && high->getSymbolOffset() == -1
                && source->getSize() == entry->getSize();
        }
    }
    const ghidra::Datatype *valueType = value == nullptr ? nullptr : value->isConstant() ? value->getType()
        : value->getHigh()->getType();
    ghidra::Address referred;
    if (source != nullptr && source->isConstant() && valueType != nullptr
        && valueType->getMetatype() == ghidra::TYPE_PTR) {
        const auto *pointer = static_cast<const ghidra::TypePointer *>(valueType);
        auto *space = pointer->getSpace();
        if (space == nullptr) space = function->getArch()->getDefaultDataSpace();
        if (space != nullptr && source->getOffset() <= space->getHighest() / space->getWordSize()) {
            auto offset = ghidra::AddrSpace::addressToByte(source->getOffset(), space->getWordSize());
            referred = ghidra::Address(space, offset);
        }
    } else if (source != nullptr && source->isWritten()) {
        const auto *definition = source->getDef();
        if (definition->code() == ghidra::CPUI_PTRSUB && definition->numInput() == 2
            && definition->getIn(1)->isConstant()) {
            const auto *baseType = definition->getIn(0)->getType();
            if (baseType->getMetatype() == ghidra::TYPE_PTR) {
                const auto *base = static_cast<const ghidra::TypePointer *>(baseType)->getPtrTo();
                if (base->getMetatype() == ghidra::TYPE_SPACEBASE)
                    referred = static_cast<const ghidra::TypeSpacebase *>(base)->getAddress(
                        definition->getIn(1)->getOffset(), definition->getIn(1)->getSize(), definition->getAddr());
            }
        }
    }
    bool globalReference = false;
    if (!referred.isInvalid() && valueType != nullptr && valueType->getMetatype() == ghidra::TYPE_PTR) {
        const auto *globalScope = function->getArch()->symboltab->getGlobalScope();
        const auto *mapping = globalScope->queryByAddr(referred, ghidra::Address());
        const auto *owner = mapping == nullptr ? nullptr : mapping->getSymbol();
        if (wholeMapping(owner, mapping) && owner->getScope()->isGlobal() && owner->isTypeLocked()) {
            symbol = owner;
            entry = mapping;
            complete = false;
            globalReference = true;
            // The source is the object's address, not a load of its value. Use native target widths/units.
            valueType = function->getArch()->types->getTypePointer(value->getSize(), owner->getType(),
                mapping->getAddr().getSpace()->getWordSize());
        }
    }
    bool global = globalReference || (complete && symbol->getScope()->isGlobal());
    json.append("{\"status\":");
    json.quote(value == nullptr || source == nullptr ? "unknown"
        : globalReference ? "global_address" : global ? "global"
        : source->isConstant() ? "constant" : computed ? "computed" : complete ? "variable" : "unknown");
    json.append(",\"data_type\":");
    if (value == nullptr) json.append("null");
    else emitType(json, valueType);
    json.append(",\"symbol_type\":");
    if (symbol == nullptr || globalReference) json.append("null");
    else emitType(json, symbol->getType());
    json.append(",\"storage\":");
    if (!complete || global || !isVariable(symbol)) json.append("null");
    else {
        json.append("{\"kind\":");
        json.quote(storageKind(entry->getAddr(), false));
        json.append(",\"space\":");
        json.quote(entry->getAddr().getSpace()->getName());
        json.append(",\"address\":");
        json.number(entry->getAddr().getOffset());
        json.append(",\"size\":");
        json.number(entry->getSize());
        json.append(",\"use_ranges\":[");
        const auto &ranges = entry->getUseLimit();
        for (auto range = ranges.begin(); range != ranges.end(); ++range) {
            countItem(count);
            if (range != ranges.begin()) json.append(",");
            json.append("{\"space\":");
            json.quote(range->getSpace()->getName());
            json.append(",\"start\":");
            json.number(range->getFirst());
            json.append(",\"end\":");
            json.number(range->getLast());
            json.append("}");
        }
        json.append("]}");
    }
    json.append(",\"raw_storage\":");
    if (entry != nullptr) emitStorage(json, entry->getAddr(), entry->getSize(), count, entry);
    else if (value != nullptr) emitStorage(json, value->getAddr(), value->getSize(), count);
    else json.append("null");
    json.append(",\"display_name\":");
    if (symbol == nullptr) json.append("null");
    else json.quote(symbol->getDisplayName());
    json.append(",\"type_locked\":");
    json.boolean(!globalReference && analystTypeLocked(symbol, saved));
    json.append(",\"global_address\":");
    if (global) json.number(entry->getAddr().getOffset());
    else json.append("null");
    json.append(",\"global_object_type\":");
    if (global) emitType(json, symbol->getType());
    else json.append("null");
    json.append(",\"global_type_locked\":");
    json.boolean(global && analystTypeLocked(symbol, saved));
    json.append("}");
}

inline std::string callEvidenceUnavailable(const ghidra::FuncCallSpecs *call) {
    const auto *op = call->getOp();
    const char *reason = nullptr;
    if (op == nullptr) reason = "missing native call operation";
    else if (op->code() != ghidra::CPUI_CALL) reason = "indirect call";
    else if (call->isDotdotdot()) reason = "variadic prototype";
    else if (call->hasInputErrors()) reason = "native input prototype errors";
    else if (call->hasOutputErrors()) reason = "native output prototype errors";
    const auto *actual = op == nullptr ? nullptr : op->getOut();
    if (reason == nullptr && actual != nullptr) {
        const auto &address = actual->getAddr();
        auto meta = actual->getHigh()->getType()->getMetatype();
        if (address.isInvalid()) reason = "actual output has no address";
        else if (address.getSpace()->getType() != ghidra::IPTR_PROCESSOR)
            reason = "actual output is not one processor register (join/internal/indirect storage)";
        else if (actual->getSize() <= 0 || actual->getSize() > 1048576) reason = "actual output width unsupported";
        else if (actual->isProtoPartial()) reason = "actual output is a native precision piece";
        else if (meta == ghidra::TYPE_STRUCT || meta == ghidra::TYPE_UNION || meta == ghidra::TYPE_ARRAY)
            reason = "actual output is aggregate";
        else if (op->getParent()->getFuncdata()->getArch()->translate->getRegisterName(address.getSpace(),
            address.getOffset(), actual->getSize()).empty()) reason = "actual output has no single register name";
    }
    const auto *output = call->getOutput();
    auto outputMeta = output->getType()->getMetatype();
    if (reason == nullptr && (output->isIndirectStorage() || output->isHiddenReturn()
        || (!output->getAddress().isInvalid() && output->getAddress().isJoin())
        || outputMeta == ghidra::TYPE_STRUCT || outputMeta == ghidra::TYPE_UNION
        || outputMeta == ghidra::TYPE_ARRAY)) reason = "prototype return uses aggregate/hidden/indirect/join storage";
    for (ghidra::int4 i = 0; reason == nullptr && i < call->numParams(); ++i) {
        const auto *parameter = call->getParam(i);
        auto meta = parameter->getType()->getMetatype();
        if (parameter->isHiddenReturn() || parameter->isIndirectStorage()
            || meta == ghidra::TYPE_STRUCT || meta == ghidra::TYPE_UNION
            || meta == ghidra::TYPE_ARRAY || parameter->getAddress().isInvalid()
            || parameter->getAddress().isJoin()) reason = "parameter uses aggregate/hidden/indirect/join storage";
    }
    if (reason == nullptr) return {};
    std::ostringstream detail;
    detail << "unsupported native call evidence: " << reason
        << "; inputs=" << (op == nullptr ? 0 : op->numInput())
        << "; prototype_parameters=" << call->numParams()
        << "; prototype_return_width=" << output->getSize()
        << "; prototype_return_meta=" << int(outputMeta)
        << "; prototype_return_locked=" << output->isTypeLocked();
    if (!output->getAddress().isInvalid())
        detail << "; prototype_return_space=" << output->getAddress().getSpace()->getName()
            << "; prototype_return_offset=" << output->getAddress().getOffset();
    if (actual != nullptr) {
        detail << "; actual_width=" << actual->getSize()
            << "; actual_meta=" << int(actual->getHigh()->getType()->getMetatype())
            << "; actual_piece=" << actual->isProtoPartial();
        if (!actual->getAddr().isInvalid())
            detail << "; actual_space=" << actual->getSpace()->getName()
                << "; actual_offset=" << actual->getOffset();
        if (!actual->getAddr().isInvalid() && actual->getSpace()->getType() == ghidra::IPTR_PROCESSOR)
            detail << "; actual_register=" << op->getParent()->getFuncdata()->getArch()->translate->getRegisterName(
                actual->getSpace(), actual->getOffset(), actual->getSize());
    } else detail << "; actual_output=none";
    return detail.str();
}

inline void emitFrameContext(Json &json, const ghidra::AddrSpace *stack) {
    if (stack == nullptr) return;
    json.append(",\"frame_context\":{\"stack_space\":");
    json.quote(stack->getName());
    json.append(",\"address_size_bytes\":");
    json.number(stack->getAddrSize());
    json.append(",\"base_convention\":");
    if (stack->getType() == ghidra::IPTR_SPACEBASE && stack->numSpacebase() == 1) {
        const auto &base = stack->getSpacebase(0);
        if (base.space != nullptr && base.size > 0) {
            json.quote("native_spacebase_register");
            json.append(",\"base_register\":{\"space\":");
            json.quote(base.space->getName());
            json.append(",\"address\":");
            json.number(base.offset);
            json.append(",\"size\":");
            json.number(nonnegative(base.size));
            json.append(",\"address_size_bytes\":");
            json.number(base.space->getAddrSize());
            json.append("}");
        } else json.quote("unknown");
    } else json.quote("unknown");
    json.append("}");
}

} // namespace results_detail

inline std::string collectResults(ghidra::Funcdata *function,
                                  const std::map<ghidra::uintb, ghidra::uintb> &externalSlots = {},
                                  const std::vector<SavedLocal> *saved = nullptr) {
    using namespace results_detail;
    if (function == nullptr) throw ghidra::LowlevelError("Missing function for structured result");
    Json json;
    size_t count = 0;
    const auto &prototype = function->getFuncProto();
    const auto *scope = function->getScopeLocal();
    json.append("{\"provenance\":\"engine_recovered\",\"signature\":{\"return_type\":");
    emitType(json, prototype.getOutputType());
    json.append(",\"calling_convention\":");
    if (prototype.hasModel()) json.quote(prototype.getModelName());
    else json.append("null");
    json.append(",\"variadic\":");
    json.boolean(prototype.isDotdotdot());
    json.append(",\"parameters\":[");
    bool firstParameter = true;
    for (ghidra::int4 i = 0; i < prototype.numParams(); ++i) {
        const auto *parameter = prototype.getParam(i);
        if (parameter->isHiddenReturn() || parameter->isIndirectStorage()) continue;
        countItem(count);
        if (!firstParameter) json.append(",");
        firstParameter = false;
        json.append("{\"name\":");
        json.quote(parameter->getName());
        json.append(",\"data_type\":");
        emitType(json, parameter->getType());
        json.append(",\"storage\":");
        const ghidra::SymbolEntry *entry = nullptr;
        if (scope != nullptr && i < scope->getCategorySize(ghidra::Symbol::function_parameter)) {
            const auto *symbol = scope->getCategorySymbol(ghidra::Symbol::function_parameter, i);
            if (symbol != nullptr) entry = symbol->getFirstWholeMap();
            if (entry != nullptr && (entry->getAddr() != parameter->getAddress()
                || entry->getSize() != parameter->getSize())) entry = nullptr;
        }
        emitStorage(json, parameter->getAddress(), parameter->getSize(), count, entry);
        json.append("}");
    }
    json.append("]},\"variables\":[");
    std::set<const ghidra::Symbol *> seen;
    if (scope != nullptr) {
        for (auto entry = scope->begin(); entry != scope->end(); ++entry) {
            countItem(count);
            const auto *symbol = (*entry)->getSymbol();
            if (!isVariable(symbol) || !seen.insert(symbol).second) continue;
            if (seen.size() != 1) json.append(",");
            emitVariable(json, symbol, count);
        }
        for (auto entry = scope->beginDynamic(); entry != scope->endDynamic(); ++entry) {
            countItem(count);
            const auto *symbol = entry->getSymbol();
            if (!isVariable(symbol) || !seen.insert(symbol).second) continue;
            if (seen.size() != 1) json.append(",");
            emitVariable(json, symbol, count);
        }
    }
    json.append("],\"blocks\":[");
    const auto &blocks = function->getBasicBlocks();
    for (ghidra::int4 i = 0; i < blocks.getSize(); ++i) {
        countItem(count);
        if (i != 0) json.append(",");
        const auto *block = blocks.getBlock(i);
        json.append("{\"index\":");
        json.number(nonnegative(block->getIndex()));
        json.append(",\"start\":");
        json.address(block->getStart());
        json.append(",\"end\":");
        json.address(block->getStop());
        json.append(",\"successors\":[");
        for (ghidra::int4 edge = 0; edge < block->sizeOut(); ++edge) {
            countItem(count);
            if (edge != 0) json.append(",");
            json.number(nonnegative(block->getOut(edge)->getIndex()));
        }
        json.append("]}");
    }
    json.append("],\"calls\":[");
    size_t argumentCount = 0;
    bool argumentBudgetExceeded = false;
    for (ghidra::int4 i = 0; i < function->numCalls(); ++i) {
        countItem(count);
        if (i != 0) json.append(",");
        const auto *call = function->getCallSpecs(i);
        const auto *op = call->getOp();
        json.append("{\"source\":");
        json.address(op == nullptr ? ghidra::Address() : op->getAddr());
        json.append(",\"target\":");
        const auto &target = call->getEntryAddress();
        auto external = target.isInvalid() ? externalSlots.end() : externalSlots.find(target.getOffset());
        if (external != externalSlots.end()) json.number(external->second);
        else json.address(target);
        json.append(",\"name\":");
        if (call->getName().empty()) json.append("null");
        else json.quote(call->getName());
        json.append(",\"indirect\":");
        json.boolean(op != nullptr && op->code() == ghidra::CPUI_CALLIND);
        const auto unavailable = callEvidenceUnavailable(call);
        if (!unavailable.empty()) {
            json.append(",\"evidence_unavailable\":");
            json.quote(unavailable);
        } else if (argumentBudgetExceeded || size_t(op->numInput() - 1) > 256 - argumentCount) {
            argumentBudgetExceeded = true;
            json.append(",\"evidence_unavailable\":");
            json.quote("native call argument evidence budget exceeded (256 per function)");
        } else {
            argumentCount += size_t(op->numInput() - 1);
            json.append(",\"arguments\":[");
            bool mapped = call->numParams() == op->numInput() - 1;
            for (ghidra::int4 slot = 1; slot < op->numInput(); ++slot) {
                countItem(count);
                if (slot != 1) json.append(",");
                json.append("{\"input_index\":");
                json.number(slot);
                json.append(",\"parameter_index\":");
                if (mapped && call->getParam(slot - 1)->getSize() == op->getIn(slot)->getSize())
                    json.number(slot - 1);
                else json.append("null");
                json.append(",\"value\":");
                emitCallValue(json, function, op->getIn(slot), count, saved);
                json.append("}");
            }
            json.append("]");
            if (op->getOut() != nullptr) {
                json.append(",\"result\":{\"value\":");
                emitCallValue(json, function, op->getOut(), count, saved);
                json.append(",\"direct_return\":");
                json.boolean(directReturn(function, op->getOut()));
                json.append("}");
            }
        }
        json.append("}");
    }
    json.append("],\"jump_tables\":[");
    for (ghidra::int4 i = 0; i < function->numJumpTables(); ++i) {
        countItem(count);
        if (i != 0) json.append(",");
        const auto *table = function->getJumpTable(i);
        json.append("{\"switch_address\":");
        json.address(table->getOpAddress());
        json.append(",\"targets\":[");
        for (ghidra::int4 target = 0; target < table->numEntries(); ++target) {
            countItem(count);
            if (target != 0) json.append(",");
            const auto address = table->getAddressByIndex(target);
            if (address.isInvalid()) throw ghidra::LowlevelError("Invalid structured jump-table target");
            json.number(address.getOffset());
        }
        json.append("],\"partial\":");
        json.boolean(table->isPartial());
        json.append(",\"case_values\":[");
        for (ghidra::int4 target = 0; target < table->numEntries(); ++target) {
            if (target != 0) json.append(",");
            if (table->isLabelled() && table->getLabelByIndex(target) != ghidra::JumpValues::NO_LABEL)
                json.number(table->getLabelByIndex(target));
            else json.append("null");
        }
        json.append("]}");
    }
    json.append("],\"diagnostics\":{\"bad_data\":");
    json.boolean(function->hasBadData());
    json.append(",\"unimplemented\":");
    json.boolean(function->hasUnimplemented());
    json.append(",\"unresolved_calls\":");
    size_t unresolvedCalls = 0;
    for (ghidra::int4 i = 0; i < function->numCalls(); ++i) {
        if (function->getCallSpecs(i)->getEntryAddress().isInvalid()) ++unresolvedCalls;
    }
    json.number(unresolvedCalls);
    json.append(",\"unresolved_indirect_jumps\":");
    size_t unresolvedJumps = 0;
    for (auto op = function->beginOpAlive(); op != function->endOpAlive(); ++op) {
        if ((*op)->code() == ghidra::CPUI_BRANCHIND && function->findJumpTable(*op) == nullptr) ++unresolvedJumps;
    }
    json.number(unresolvedJumps);
    json.append(",\"partial_jump_tables\":");
    size_t partialTables = 0;
    for (ghidra::int4 i = 0; i < function->numJumpTables(); ++i) {
        if (function->getJumpTable(i)->isPartial()) ++partialTables;
    }
    json.number(partialTables);
    json.append(",\"warnings\":[");
    const auto *comments = function->getArch()->commentdb;
    bool firstWarning = true;
    for (auto entry = comments->beginComment(function->getAddress());
         entry != comments->endComment(function->getAddress()); ++entry) {
        const auto *warning = *entry;
        if ((warning->getType() & (ghidra::Comment::warning | ghidra::Comment::warningheader)) == 0) continue;
        countItem(count);
        if (!firstWarning) json.append(",");
        firstWarning = false;
        bool header = (warning->getType() & ghidra::Comment::warningheader) != 0;
        json.append("{\"kind\":");
        json.quote(header ? "header" : "body");
        json.append(",\"address\":");
        if (header) json.append("null"); else json.address(warning->getAddr());
        json.append(",\"message\":");
        json.quote(warning->getText());
        json.append("}");
    }
    json.append("]}");
    emitFrameContext(json, function->getArch()->getStackSpace());
    json.append("}");
    return json.take();
}

} // namespace rampage
