#pragma once

#include "database.hh"
#include "funcdata.hh"
#include "grammar.hh"
#include "varmap.hh"

#include <set>
#include <map>
#include <cstddef>
#include <cstdint>
#include <cctype>
#include <sstream>
#include <vector>

namespace rampage {

struct NativeLocalRange {
    const char *space;
    uint64_t start;
    uint64_t end;
};

struct NativeLocalOverride {
    uint32_t kind;
    const char *space;
    uint64_t address;
    uint32_t size;
    const NativeLocalRange *ranges;
    size_t rangeCount;
    const char *name;
    const char *dataType;
};

struct LocalRange {
    ghidra::AddrSpace *space;
    ghidra::uintb start;
    ghidra::uintb end;
};

struct LocalOverride {
    ghidra::Address address;
    ghidra::int4 size;
    std::vector<LocalRange> ranges;
    std::string name;
    ghidra::Datatype *type;
};

inline bool matchesLocal(const ghidra::SymbolEntry *entry, const LocalOverride &key) {
    if (entry->isDynamic() || entry->isPiece() || entry->getOffset() != 0
        || entry->getAddr() != key.address || entry->getSize() != key.size) return false;
    const auto &ranges = entry->getUseLimit();
    auto actual = ranges.begin();
    for (const auto &range : key.ranges) {
        if (actual == ranges.end() || actual->getSpace() != range.space
            || actual->getFirst() != range.start || actual->getLast() != range.end) return false;
        ++actual;
    }
    return actual == ranges.end();
}

inline std::string localTypeDeclaration(ghidra::Architecture *arch, const std::string &declaration) {
    using namespace ghidra;
    std::string result;
    for (size_t index = 0; index < declaration.size();) {
        unsigned char ch = declaration[index];
        if (!std::isalpha(ch) && ch != '_') {
            result.push_back(declaration[index++]);
            continue;
        }
        size_t first = index++;
        while (index < declaration.size()) {
            ch = declaration[index];
            if (!std::isalnum(ch) && ch != '_') break;
            ++index;
        }
        std::string word = declaration.substr(first, index - first);
        if (word != "struct" && word != "union" && word != "enum") {
            result += word;
            continue;
        }
        while (index < declaration.size() && std::isspace(static_cast<unsigned char>(declaration[index]))) ++index;
        first = index;
        if (index == declaration.size()
            || (!std::isalpha(static_cast<unsigned char>(declaration[index])) && declaration[index] != '_'))
            throw LowlevelError("Local aggregate type requires an already loaded named tag");
        ++index;
        while (index < declaration.size()) {
            ch = declaration[index];
            if (!std::isalnum(ch) && ch != '_') break;
            ++index;
        }
        std::string tag = declaration.substr(first, index - first);
        Datatype *type = arch->types->findByName(tag);
        bool matches = type != nullptr && (word == "struct" ? type->getMetatype() == TYPE_STRUCT
            : word == "union" ? type->getMetatype() == TYPE_UNION : type->isEnumType());
        if (!matches)
            throw LowlevelError("Local aggregate tag does not match an already loaded native type");
        // Known tags lex as TYPE_NAME, which cannot follow STRUCT/UNION/ENUM in Ghidra's grammar.
        // Use the same checked native type directly; the C body is never rewritten.
        result += tag;
    }
    return result;
}

inline std::vector<LocalOverride> prepareLocals(ghidra::Architecture *arch,
                                              const NativeLocalOverride *records, size_t count) {
    using namespace ghidra;
    if (count > 256) throw LowlevelError("Local override count exceeds 256");
    std::vector<LocalOverride> result;
    result.reserve(count);
    for (size_t index = 0; index < count; ++index) {
        const auto &record = records[index];
        AddrSpace *space = arch->getSpaceByName(record.space);
        spacetype expected = record.kind == 0 ? IPTR_PROCESSOR : IPTR_SPACEBASE;
        if (record.kind > 1 || space == nullptr || space->getType() != expected || record.size == 0
            || record.size > 1048576 || record.address > space->getHighest()
            || record.size - 1 > space->getHighest() - record.address || record.rangeCount > 256)
            throw LowlevelError("Unsupported local variable storage selector");
        LocalOverride item{Address(space, record.address), int4(record.size), {},
                           record.name == nullptr ? "" : record.name, nullptr};
        for (size_t i = 0; i < record.rangeCount; ++i) {
            const auto &range = record.ranges[i];
            AddrSpace *useSpace = arch->getSpaceByName(range.space);
            if (useSpace == nullptr || useSpace->getType() != IPTR_PROCESSOR
                || range.start > range.end || range.end > useSpace->getHighest())
                throw LowlevelError("Invalid local variable use range");
            item.ranges.push_back({useSpace, range.start, range.end});
        }
        if (record.dataType != nullptr) {
            std::string declaration(record.dataType);
            if (declaration.find_first_of(";{}=()[]") != std::string::npos)
                throw LowlevelError("Local type requires a scalar or pointer abstract C declaration");
            std::string name;
            std::istringstream input(localTypeDeclaration(arch, declaration) + " __rampage_local_override");
            item.type = parse_type(input, name, arch);
            input >> std::ws;
            if (name != "__rampage_local_override" || !input.eof() || item.type->getSize() != item.size
                || item.type->getMetatype() == TYPE_CODE || item.type->getMetatype() == TYPE_VOID)
                throw LowlevelError("Local override type must have exactly the selected storage size");
        }
        result.push_back(std::move(item));
    }
    return result;
}

struct SavedLocal {
    ghidra::Symbol *symbol;
    ghidra::Datatype *type;
    std::string name;
    ghidra::uint4 locks;
    bool isolated;
};

inline void restoreLocals(ghidra::Scope *scope, std::vector<SavedLocal> &saved) {
    using namespace ghidra;
    if (saved.empty()) return;
    std::set<const Symbol *> live;
    for (auto entry = scope->begin(); entry != scope->end(); ++entry) live.insert((*entry)->getSymbol());
    while (!saved.empty()) {
        const auto &original = saved.back();
        if (live.count(original.symbol) == 0)
            throw LowlevelError("Native analysis removed an overridden symbol; rebuild the decompiler");
        scope->retypeSymbol(original.symbol, original.type);
        scope->renameSymbol(original.symbol, original.name);
        original.symbol->setIsolated(original.isolated);
        scope->clearAttribute(original.symbol, Varnode::typelock | Varnode::namelock);
        scope->setAttribute(original.symbol, original.locks);
        saved.pop_back();
    }
}

inline void applyLocals(ghidra::Funcdata *function, const std::vector<LocalOverride> &overrides,
                        std::vector<SavedLocal> &saved) {
    using namespace ghidra;
    ScopeLocal *scope = function->getScopeLocal();
    std::vector<Symbol *> matches;
    std::set<Symbol *> selected;
    // Resolve the complete batch before changing any symbol. Never use generated names as selectors.
    for (const auto &item : overrides) {
        Symbol *match = nullptr;
        for (auto entry = scope->begin(); entry != scope->end(); ++entry) {
            const auto *mapping = *entry;
            Symbol *symbol = mapping->getSymbol();
            if (!matchesLocal(mapping, item)) continue;
            if (symbol->getCategory() != Symbol::no_category
                && symbol->getCategory() != Symbol::function_parameter) continue;
            if (symbol->numEntries() != 1 || symbol->getType()->getSize() != item.size)
                throw LowlevelError("Local selector requires one whole mapping of the owning symbol");
            if (match != nullptr) throw LowlevelError("Ambiguous local variable storage selector");
            match = symbol;
        }
        if (match == nullptr) throw LowlevelError("Local variable storage selector did not match a recovered symbol");
        if (!selected.insert(match).second) throw LowlevelError("Duplicate local variable storage selector");
        matches.push_back(match);
    }
    std::map<Symbol *, std::string> finalNames;
    std::set<std::string> selectedNames;
    for (size_t i = 0; i < matches.size(); ++i) {
        const std::string &name = overrides[i].name.empty() ? matches[i]->getName() : overrides[i].name;
        if (!selectedNames.insert(name).second)
            throw LowlevelError("Local override final name is already used");
        finalNames.emplace(matches[i], name);
    }
    for (const auto &desired : finalNames) {
        std::vector<Symbol *> named;
        scope->queryByName(desired.second, named);
        for (auto *other : named) {
            if (other == desired.first) continue;
            auto renamed = finalNames.find(other);
            if (renamed == finalNames.end() || renamed->second == desired.second)
                throw LowlevelError("Local override final name is already used");
        }
    }
    saved.reserve(matches.size() + function->getFuncProto().numParams());
    bool parameterSelected = false;
    for (size_t i = 0; i < matches.size(); ++i) {
        Symbol *symbol = matches[i];
        const auto &item = overrides[i];
        parameterSelected |= symbol->getCategory() == Symbol::function_parameter;
        saved.push_back({symbol, symbol->getType(), symbol->getName(),
                         symbol->getFlags() & (Varnode::typelock | Varnode::namelock), symbol->isIsolated()});
        Datatype *type = item.type;
        if (type == nullptr) type = symbol->isTypeLocked() ? symbol->getType()
            : function->getArch()->types->getBase(item.size, TYPE_UNKNOWN);
        scope->retypeSymbol(symbol, type);
        // A size-locked unknown keeps rename-only symbols alive while allowing native type inference.
        scope->setAttribute(symbol, Varnode::typelock);
        if (item.type != nullptr) symbol->setIsolated(true);
        if (!item.name.empty()) {
            scope->renameSymbol(symbol, item.name);
            scope->setAttribute(symbol, Varnode::namelock);
        }
    }
    // Ghidra treats the first parameter's type lock as the prototype input lock. Preserve the entire
    // recovered input set for this pass, including when only a later parameter is selected.
    if (parameterSelected) {
        for (int4 i = 0; i < scope->getCategorySize(Symbol::function_parameter); ++i) {
            Symbol *symbol = scope->getCategorySymbol(Symbol::function_parameter, i);
            if (symbol == nullptr || selected.count(symbol) != 0) continue;
            saved.push_back({symbol, symbol->getType(), symbol->getName(),
                             symbol->getFlags() & (Varnode::typelock | Varnode::namelock), symbol->isIsolated()});
            scope->setAttribute(symbol, Varnode::typelock | Varnode::namelock);
        }
    }
}

inline void verifyLocals(ghidra::Funcdata *function, const std::vector<LocalOverride> &overrides,
                         const std::vector<SavedLocal> &saved) {
    using namespace ghidra;
    std::set<const Symbol *> live;
    const auto *scope = function->getScopeLocal();
    for (auto entry = scope->begin(); entry != scope->end(); ++entry) live.insert((*entry)->getSymbol());
    for (size_t i = 0; i < overrides.size(); ++i) {
        const auto &item = overrides[i];
        const Symbol *symbol = saved[i].symbol;
        if (live.count(symbol) == 0 || symbol->numEntries() != 1 || !matchesLocal(symbol->getMapEntry(0), item)
            || (!item.name.empty() && symbol->getName() != item.name)
            || (item.type != nullptr && symbol->getType() != item.type))
            throw LowlevelError("Native local override was not retained by analysis");
    }
}

} // namespace rampage
