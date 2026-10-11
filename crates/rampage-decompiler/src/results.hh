#pragma once

#include "funcdata.hh"
#include "architecture.hh"
#include "database.hh"
#include "op.hh"
#include "type.hh"
#include "translate.hh"
#include "comment.hh"

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
    return symbol->getCategory() == ghidra::Symbol::no_category
        || symbol->getCategory() == ghidra::Symbol::function_parameter;
}

} // namespace results_detail

inline std::string collectResults(ghidra::Funcdata *function,
                                  const std::map<ghidra::uintb, ghidra::uintb> &externalSlots = {}) {
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
    for (ghidra::int4 i = 0; i < prototype.numParams(); ++i) {
        countItem(count);
        if (i != 0) json.append(",");
        const auto *parameter = prototype.getParam(i);
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
    json.append("]}}");
    return json.take();
}

} // namespace rampage
