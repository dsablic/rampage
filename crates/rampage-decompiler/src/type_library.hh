#ifndef RAMPAGE_TYPE_LIBRARY_HH
#define RAMPAGE_TYPE_LIBRARY_HH

#include "grammar.hh"
#include "results.hh"
#include <algorithm>
#include <cctype>
#include <map>
#include <set>

namespace rampage {
namespace type_library {

using namespace ghidra;
constexpr size_t maxItems = 256;
constexpr size_t maxJson = 1024 * 1024;
constexpr size_t maxDeclarations = 64 * 1024;

class Json {
    results_detail::Json inner;
    size_t bytes = 0;
public:
    void append(const char *text) {
        size_t length = std::strlen(text);
        if (length > maxJson - bytes) throw LowlevelError("Type inventory JSON limit exceeded (1 MiB)");
        bytes += length;
        inner.append(text);
    }
    void number(uint64_t value) { append(std::to_string(value).c_str()); }
    void quote(const std::string &text) {
        results_detail::Json encoded;
        encoded.quote(text);
        append(encoded.take().c_str());
    }
    std::string take() { return inner.take(); }
};

inline void bounded(size_t count) {
    if (count > maxItems) throw LowlevelError("Type library item limit exceeded (256)");
}

inline std::map<std::string, Datatype *> snapshot(TypeFactory *factory) {
    std::map<std::string, Datatype *> result;
    for (Datatype *type : factory->namedTypes()) {
        if (!type->getName().empty()) result.emplace(type->getName(), type);
    }
    return result;
}

inline std::string typeName(Datatype *type, size_t depth = 0) {
    if (depth > 32) throw LowlevelError("Type reference depth limit exceeded (32)");
    if (!type->getName().empty()) return type->getName();
    if (type->getMetatype() == TYPE_PTR)
        return typeName(static_cast<TypePointer *>(type)->getPtrTo(), depth + 1) + " *";
    if (type->getMetatype() == TYPE_ARRAY) {
        std::string dimensions;
        Datatype *element = type;
        while (element->getMetatype() == TYPE_ARRAY && element->getName().empty()) {
            if (++depth > 32) throw LowlevelError("Type reference depth limit exceeded (32)");
            TypeArray *array = static_cast<TypeArray *>(element);
            dimensions += "[" + std::to_string(array->numElements()) + "]";
            element = array->getBase();
        }
        return typeName(element, depth) + dimensions;
    }
    if (type->getMetatype() == TYPE_CODE) return "function";
    return type->getMetatype() == TYPE_STRUCT ? "anonymous struct"
        : type->getMetatype() == TYPE_UNION ? "anonymous union" : "anonymous";
}

inline bool sized(Datatype *type) {
    return !type->isIncomplete() && type->getMetatype() != TYPE_VOID
        && type->getMetatype() != TYPE_CODE && type->getSize() > 0;
}

inline void size(Json &json, Datatype *type) {
    if (sized(type)) json.number(type->getSize());
    else json.append("null");
}

inline void identity(Json &json, Datatype *type, bool expand, size_t depth, size_t &nodes) {
    if (depth > 32 || ++nodes > 4096) throw LowlevelError("Structural type identity depth/node limit exceeded");
    if (!expand && !type->getName().empty()) {
        json.append("{\"reference\":"); json.quote(type->getName()); json.append("}");
        return;
    }
    json.append("{\"kind\":"); json.number(type->getMetatype());
    json.append(",\"size\":"); size(json, type);
    json.append(",\"alignment\":");
    if (sized(type) && type->getAlignment() > 0) json.number(type->getAlignment());
    else json.append("null");
    auto child = [&](Datatype *value) { identity(json, value, false, depth + 1, nodes); };
    if (type->getTypedef() != nullptr) {
        json.append(",\"typedef\":"); child(type->getTypedef());
    } else if (type->getMetatype() == TYPE_PTR) {
        json.append(",\"target\":"); child(static_cast<TypePointer *>(type)->getPtrTo());
    } else if (type->getMetatype() == TYPE_ARRAY) {
        auto array = static_cast<TypeArray *>(type);
        json.append(",\"length\":"); json.number(array->numElements());
        json.append(",\"element\":"); child(array->getBase());
    } else if (type->getMetatype() == TYPE_CODE) {
        auto code = static_cast<TypeCode *>(type);
        const PrototypePieces *decl = code->getDeclaration();
        const FuncProto *lowered = code->getPrototype();
        json.append(",\"signature_known\":"); json.append(decl == nullptr ? "false" : "true");
        json.append(",\"calling_convention\":");
        if (decl != nullptr && decl->model != nullptr) json.quote(decl->model->getName());
        else if (lowered != nullptr && lowered->hasModel()) json.quote(lowered->getModelName());
        else json.append("null");
        if (decl != nullptr) {
            bounded(decl->intypes.size());
            json.append(",\"return_type\":"); child(decl->outtype);
            json.append(",\"variadic\":"); json.append(decl->firstVarArgSlot >= 0 ? "true" : "false");
            json.append(",\"parameters\":[");
            for (size_t i = 0; i < decl->intypes.size(); ++i) {
                if (i) json.append(",");
                json.append("{\"name\":"); json.quote(i < decl->innames.size() ? decl->innames[i] : "");
                json.append(",\"type\":"); child(decl->intypes[i]); json.append("}");
            }
            json.append("]");
        } else if (lowered != nullptr) {
            bounded(lowered->numParams());
            json.append(",\"abi_signature\":{\"return_type\":"); child(lowered->getOutputType());
            json.append(",\"parameters\":[");
            for (int4 i = 0; i < lowered->numParams(); ++i) {
                if (i) json.append(",");
                ProtoParameter *parameter = lowered->getParam(i);
                json.append("{\"type\":"); child(parameter->getType());
                json.append(",\"hidden_return\":"); json.append(parameter->isHiddenReturn() ? "true" : "false");
                json.append(",\"indirect_storage\":"); json.append(parameter->isIndirectStorage() ? "true" : "false");
                json.append("}");
            }
            json.append("],\"variadic\":"); json.append(lowered->isDotdotdot() ? "true" : "false");
            json.append("}");
        }
    } else if (type->getMetatype() == TYPE_STRUCT || type->getMetatype() == TYPE_UNION) {
        if (type->hasBitfields()) throw LowlevelError("Bitfield structural identity is not supported");
        bounded(type->numDepend());
        json.append(",\"fields\":[");
        for (int4 i = 0; i < type->numDepend(); ++i) {
            const TypeField *field = type->getMetatype() == TYPE_STRUCT
                ? &*(static_cast<TypeStruct *>(type)->beginField() + i) : static_cast<TypeUnion *>(type)->getField(i);
            if (i) json.append(",");
            json.append("{\"name\":"); json.quote(field->name);
            json.append(",\"offset\":"); json.number(field->offset);
            json.append(",\"type\":"); child(field->type); json.append("}");
        }
        json.append("]");
    } else if (type->isEnumType()) {
        auto enumeration = static_cast<TypeEnum *>(type);
        json.append(",\"enum_values\":[");
        size_t count = 0;
        for (auto it = enumeration->beginEnum(); it != enumeration->endEnum(); ++it) {
            bounded(++count);
            if (count != 1) json.append(",");
            json.append("{\"name\":"); json.quote(it->second);
            json.append(",\"value\":"); json.quote(std::to_string(it->first)); json.append("}");
        }
        json.append("]");
    }
    json.append("}");
}

inline void identity(Json &json, Datatype *type, bool expand) {
    size_t nodes = 0;
    identity(json, type, expand, 0, nodes);
}

inline void dependencies(Datatype *type, std::set<std::string> &names,
                         std::set<Datatype *> &seen, bool byValue, size_t depth = 0) {
    if (depth > 32) throw LowlevelError("Type dependency depth limit exceeded (32)");
    if (!seen.insert(type).second) return;
    if (byValue && (type->getMetatype() == TYPE_PTR || type->getMetatype() == TYPE_CODE)) return;
    if (!type->getName().empty()) {
        if (!type->isCoreType()) names.insert(type->getName());
        bounded(names.size());
        return;
    }
    if (type->numDepend() > int4(maxItems)) throw LowlevelError("Type dependency limit exceeded (256)");
    for (int4 i = 0; i < type->numDepend(); ++i)
        dependencies(type->getDepend(i), names, seen, byValue, depth + 1);
    if (type->getMetatype() == TYPE_CODE) {
        const PrototypePieces *decl = static_cast<TypeCode *>(type)->getDeclaration();
        if (decl != nullptr) {
            dependencies(decl->outtype, names, seen, byValue, depth + 1);
            bounded(decl->intypes.size());
            for (Datatype *parameter : decl->intypes)
                dependencies(parameter, names, seen, byValue, depth + 1);
        } else {
            const FuncProto *abi = static_cast<TypeCode *>(type)->getPrototype();
            if (abi != nullptr) {
                bounded(abi->numParams());
                dependencies(abi->getOutputType(), names, seen, byValue, depth + 1);
                for (int4 i = 0; i < abi->numParams(); ++i)
                    dependencies(abi->getParam(i)->getType(), names, seen, byValue, depth + 1);
            }
        }
    }
}

inline void emitDependencies(Json &json, Datatype *type, bool byValue) {
    std::set<std::string> names;
    std::set<Datatype *> seen;
    if (type->getTypedef() != nullptr) dependencies(type->getTypedef(), names, seen, byValue);
    else {
        bounded(type->numDepend());
        for (int4 i = 0; i < type->numDepend(); ++i)
            dependencies(type->getDepend(i), names, seen,
                byValue && type->getMetatype() != TYPE_PTR && type->getMetatype() != TYPE_CODE);
        if (byValue && (type->getMetatype() == TYPE_PTR || type->getMetatype() == TYPE_CODE)) names.clear();
    }
    json.append("[");
    bool comma = false;
    for (const auto &name : names) {
        if (comma) json.append(",");
        json.quote(name);
        comma = true;
    }
    json.append("]");
}

inline void emit(Json &json, Datatype *type, const std::map<Datatype *, int4> &packing) {
    json.append("{\"name\":"); json.quote(type->getName());
    const char *kind = type->getTypedef() != nullptr ? "typedef"
        : type->isEnumType() ? "enum"
        : type->getMetatype() == TYPE_STRUCT ? "struct"
        : type->getMetatype() == TYPE_UNION ? "union"
        : type->getMetatype() == TYPE_PTR ? "pointer"
        : type->getMetatype() == TYPE_ARRAY ? "array"
        : type->getMetatype() == TYPE_CODE ? "function"
        : type->getMetatype() == TYPE_VOID ? "void" : "primitive";
    json.append(",\"kind\":"); json.quote(kind);
    json.append(",\"size\":"); size(json, type);
    json.append(",\"alignment\":");
    if (sized(type) && type->getAlignment() > 0) json.number(type->getAlignment());
    else json.append("null");
    json.append(",\"incomplete\":"); json.append(type->isIncomplete() ? "true" : "false");
    json.append(",\"packing\":");
    Datatype *base = type;
    std::set<Datatype *> aliases;
    while (base->getTypedef() != nullptr && aliases.insert(base).second) {
        if (aliases.size() > 32) throw LowlevelError("Typedef reference depth limit exceeded (32)");
        base = base->getTypedef();
    }
    auto packed = packing.find(base);
    if (packed == packing.end()) json.append("null"); else json.number(packed->second);
    json.append(",\"identity\":"); identity(json, type, true);
    json.append(",\"fields\":[");
    bounded(type->numDepend());
    bool comma = false;
    if (type->getMetatype() == TYPE_STRUCT || type->getMetatype() == TYPE_UNION) {
        if (type->hasBitfields()) throw LowlevelError("Bitfield type inventory is not supported");
        for (int4 i = 0; i < type->numDepend(); ++i) {
            const TypeField *field = type->getMetatype() == TYPE_STRUCT
                ? &*(static_cast<TypeStruct *>(type)->beginField() + i) : static_cast<TypeUnion *>(type)->getField(i);
            if (comma) json.append(",");
            json.append("{\"name\":"); json.quote(field->name);
            json.append(",\"offset\":"); json.number(field->offset);
            json.append(",\"type_name\":"); json.quote(typeName(field->type));
            json.append(",\"size\":"); size(json, field->type);
            json.append(",\"identity\":"); identity(json, field->type, false);
            json.append("}"); comma = true;
        }
    }
    json.append("],\"enum_values\":[");
    if (type->isEnumType()) {
        auto enumeration = static_cast<TypeEnum *>(type);
        comma = false;
        size_t count = 0;
        for (auto it = enumeration->beginEnum(); it != enumeration->endEnum(); ++it) {
            bounded(++count);
            if (comma) json.append(",");
            json.append("{\"name\":"); json.quote(it->second);
            json.append(",\"value\":");
            json.quote(type->getMetatype() == TYPE_INT
                ? std::to_string(sign_extend(it->first, type->getSize() * 8 - 1)) : std::to_string(it->first));
            json.append("}"); comma = true;
        }
    }
    json.append("],\"target\":");
    Datatype *target = type->getTypedef();
    if (target == nullptr && type->getMetatype() == TYPE_PTR) target = static_cast<TypePointer *>(type)->getPtrTo();
    if (target == nullptr && type->getMetatype() == TYPE_ARRAY) target = static_cast<TypeArray *>(type)->getBase();
    if (target == nullptr) json.append("null"); else json.quote(typeName(target));
    json.append(",\"array_length\":");
    if (type->getMetatype() == TYPE_ARRAY) json.number(static_cast<TypeArray *>(type)->numElements());
    else json.append("null");
    json.append(",\"callback\":");
    Datatype *code = type;
    if (code->getMetatype() == TYPE_PTR) code = static_cast<TypePointer *>(code)->getPtrTo();
    const PrototypePieces *decl = code->getMetatype() == TYPE_CODE
        ? static_cast<TypeCode *>(code)->getDeclaration() : nullptr;
    if (decl == nullptr) json.append("null");
    else {
        bounded(decl->intypes.size());
        json.append("{\"return_type\":"); json.quote(typeName(decl->outtype));
        json.append(",\"variadic\":"); json.append(decl->firstVarArgSlot >= 0 ? "true" : "false");
        json.append(",\"calling_convention\":");
        if (decl->model == nullptr) json.append("null"); else json.quote(decl->model->getName());
        json.append(",\"parameters\":[");
        for (size_t i = 0; i < decl->intypes.size(); ++i) {
            if (i) json.append(",");
            json.append("{\"name\":"); json.quote(i < decl->innames.size() ? decl->innames[i] : "");
            json.append(",\"type_name\":"); json.quote(typeName(decl->intypes[i]));
            json.append("}");
        }
        json.append("]}");
    }
    json.append(",\"dependencies\":"); emitDependencies(json, type, false);
    json.append(",\"by_value_dependencies\":"); emitDependencies(json, type, true);
    json.append("}");
}

// Assertion-only admission. Inspection remains available for incomplete and unsupported native types.
inline void assertCompleteGraph(Datatype *type, std::set<Datatype *> &seen, size_t depth = 0) {
    if (!seen.insert(type).second) return;
    if (depth > 32 || seen.size() > 4096)
        throw LowlevelError("Named assertion native graph exceeds depth/node bounds (32/4096)");
    if (type->isIncomplete() || type->hasBitfields())
        throw LowlevelError("Named assertion requires complete non-bitfield native types");
    type_metatype kind = type->getMetatype();
    if (kind != TYPE_VOID && kind != TYPE_INT && kind != TYPE_UINT && kind != TYPE_BOOL
        && kind != TYPE_FLOAT && kind != TYPE_CODE && kind != TYPE_PTR && kind != TYPE_ARRAY
        && kind != TYPE_STRUCT && kind != TYPE_UNION)
        throw LowlevelError("Named assertion native type kind is unsupported");
    if (kind != TYPE_VOID && kind != TYPE_CODE
        && (type->getSize() <= 0 || type->getSize() > 1048576 || type->getAlignment() <= 0))
        throw LowlevelError("Named assertion native size/alignment is unavailable or unsupported");
    bounded(type->numDepend());
    for (int4 i = 0; i < type->numDepend(); ++i)
        assertCompleteGraph(type->getDepend(i), seen, depth + 1);
    if (type->getTypedef() != nullptr) assertCompleteGraph(type->getTypedef(), seen, depth + 1);
    if (kind == TYPE_CODE) {
        const PrototypePieces *decl = static_cast<TypeCode *>(type)->getDeclaration();
        if (decl == nullptr || decl->model == nullptr)
            throw LowlevelError("Named assertion requires a declared callback and native model");
        bounded(decl->intypes.size());
        assertCompleteGraph(decl->outtype, seen, depth + 1);
        for (Datatype *parameter : decl->intypes) assertCompleteGraph(parameter, seen, depth + 1);
    }
}

struct Token { std::string text; size_t start; size_t end; };

inline std::vector<Token> tokenize(const std::string &text) {
    std::vector<Token> tokens;
    for (size_t i = 0; i < text.size();) {
        unsigned char ch = text[i];
        if (std::isspace(ch)) { ++i; continue; }
        size_t start = i++;
        if (std::isalnum(ch) || ch == '_') {
            while (i < text.size() && (std::isalnum(static_cast<unsigned char>(text[i])) || text[i] == '_')) ++i;
            if (i - start > 256) throw ParseError("Type library token/name limit exceeded (256 bytes)");
        } else if (ch == '.' && i + 1 < text.size() && text[i] == '.' && text[i + 1] == '.') {
            i += 2;
        } else if (ch == '\'') {
            while (i < text.size()) {
                char next = text[i++];
                if (next == '\\' && i < text.size()) ++i;
                else if (next == '\'') break;
            }
        }
        tokens.push_back({text.substr(start, i - start), start, i});
    }
    return tokens;
}

inline std::string normalize(const std::vector<Token> &tokens, TypeFactory *factory) {
    std::string text;
    for (size_t i = 0; i < tokens.size();) {
        const std::string &word = tokens[i].text;
        if (word == "-" && i + 1 < tokens.size() && !tokens[i + 1].text.empty()
            && std::isdigit(static_cast<unsigned char>(tokens[i + 1].text[0]))) {
            text += "-" + tokens[i + 1].text + " "; i += 2; continue;
        }
        auto builtin = [](const std::string &part) {
            return part == "signed" || part == "unsigned" || part == "short" || part == "long"
                || part == "int" || part == "char" || part == "float" || part == "double" || part == "_Bool";
        };
        if (!builtin(word)) { text += word + " "; ++i; continue; }
        std::map<std::string, int> counts;
        std::string qualifiers;
        size_t end = i;
        for (; end < tokens.size(); ++end) {
            const auto &part = tokens[end].text;
            if (builtin(part)) ++counts[part];
            else if (part == "const" || part == "volatile" || part == "restrict") qualifiers += part + " ";
            else break;
        }
        for (const auto &entry : counts) {
            if (entry.second > (entry.first == "long" ? 2 : 1)) throw ParseError("Duplicate C type specifier");
        }
        int sign = counts["signed"] + counts["unsigned"];
        int rank = counts["short"] + counts["long"];
        int other = counts["float"] + counts["double"] + counts["_Bool"];
        if (sign > 1 || (counts["short"] && counts["long"]) || other > 1
            || (counts["char"] && (rank || counts["int"] || other))
            || (other && (sign || counts["int"] || counts["short"] || counts["char"]))
            || ((counts["float"] || counts["_Bool"]) && rank))
            throw ParseError("Contradictory C type specifiers");
        if (counts["double"] && counts["long"])
            throw ParseError("Long double requires an explicit native sized floating-point type");
        if (other) text += counts["float"] ? "float4 " : counts["double"] ? "float8 " : "bool ";
        else if (counts["char"] && !sign) text += "char ";
        else {
            int4 width = counts["char"] ? factory->getSizeOfChar() : counts["short"] ? 2
                : counts["long"] == 2 ? 8 : counts["long"] ? factory->getSizeOfLong() : factory->getSizeOfInt();
            text += std::string(counts["unsigned"] ? "uint" : "int") + std::to_string(width) + " ";
        }
        text += qualifiers;
        i = end;
    }
    return text;
}

inline void validateGraph(Datatype *type, std::set<Datatype *> &seen, size_t depth = 0) {
    if (!seen.insert(type).second) return;
    if (depth > 32 || seen.size() > 4096) throw ParseError("Type graph depth/node limit exceeded");
    if (type->getSize() > 1048576) throw ParseError("Reachable type size limit exceeded (1 MiB)");
    if (type->hasBitfields()) throw ParseError("Bitfield type libraries are not supported");
    if (type->getMetatype() == TYPE_ARRAY) {
        Datatype *element = static_cast<TypeArray *>(type)->getBase();
        if (element->isIncomplete() || element->getMetatype() == TYPE_CODE || element->getMetatype() == TYPE_VOID)
            throw ParseError("Array elements require complete object types");
    }
    bounded(type->numDepend());
    for (int4 i = 0; i < type->numDepend(); ++i) validateGraph(type->getDepend(i), seen, depth + 1);
    if (type->getTypedef() != nullptr) validateGraph(type->getTypedef(), seen, depth + 1);
    if (type->getMetatype() == TYPE_CODE) {
        const PrototypePieces *decl = static_cast<TypeCode *>(type)->getDeclaration();
        if (decl != nullptr) {
            bounded(decl->intypes.size());
            validateGraph(decl->outtype, seen, depth + 1);
            for (Datatype *parameter : decl->intypes) validateGraph(parameter, seen, depth + 1);
        } else {
            const FuncProto *abi = static_cast<TypeCode *>(type)->getPrototype();
            if (abi != nullptr) {
                bounded(abi->numParams());
                validateGraph(abi->getOutputType(), seen, depth + 1);
                for (int4 i = 0; i < abi->numParams(); ++i)
                    validateGraph(abi->getParam(i)->getType(), seen, depth + 1);
            }
        }
    }
}

inline std::vector<std::string> parse(Architecture *arch, const std::string &text, int4 packing,
                                     std::map<Datatype *, int4> &packedTypes) {
    if (text.empty() || text.size() > maxDeclarations) throw ParseError("Type declarations require 1..65536 bytes");
    if (packing != 0 && packing != 1 && packing != 2 && packing != 4 && packing != 8 && packing != 16)
        throw ParseError("Packing must be 1, 2, 4, 8, or 16");
    std::vector<Token> tokens = tokenize(text);
    std::vector<std::string> requested;
    std::set<std::string> requestedSet;
    size_t start = 0;
    int depth = 0;
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i].text == "{") { if (++depth > 32) throw ParseError("Declaration nesting exceeds 32"); }
        if (tokens[i].text == "}" && --depth < 0) throw ParseError("Unbalanced declaration braces");
        if (tokens[i].text != ";" || depth != 0) continue;
        auto before = snapshot(arch->types);
        std::set<std::string> incompleteBefore;
        for (const auto &entry : before) {
            if (entry.second->isIncomplete()) incompleteBefore.insert(entry.first);
        }
        std::vector<Token> declaration(tokens.begin() + start, tokens.begin() + i + 1);
        start = i + 1;
        // A tag and its identical typedef share Ghidra's single type namespace.
        bool sameTagAlias = declaration.size() >= 5 && declaration[0].text == "typedef"
            && (declaration[1].text == "struct" || declaration[1].text == "union" || declaration[1].text == "enum")
            && declaration[2].text == declaration[declaration.size() - 2].text
            && (declaration[3].text == "{" || declaration.size() == 5);
        if (sameTagAlias) { declaration.erase(declaration.end() - 2); declaration.erase(declaration.begin()); }
        std::istringstream input(normalize(declaration, arch->types));
        CParse parser(arch, 65536);
        parser.setTypeLibrary(packing);
        if (!parser.parseStream(input, CParse::doc_declaration)) throw ParseError(parser.getError());
        if (packing != 0) {
            for (Datatype *aggregate : parser.getLibraryAggregates()) packedTypes[aggregate] = packing;
        }
        auto decls = parser.getResultDeclarations();
        if (decls == nullptr || decls->empty()) throw ParseError("Missing named type declaration");
        bounded(decls->size());
        for (TypeDeclarator *decl : *decls) {
            if (!decl->isValid()) throw ParseError("Invalid type declaration");
            bool alias = decl->hasProperty(CParse::f_typedef);
            if (decl->hasProperty(CParse::f_extern | CParse::f_static | CParse::f_auto | CParse::f_register)
                || (!alias && (!decl->getIdentifier().empty() || decl->numModifiers() != 0)))
                throw ParseError("Type libraries reject function and object declarations");
            Datatype *type = alias ? decl->buildType(arch) : decl->getBaseType();
            if (type->getSize() > 1048576) throw ParseError("Type library type size limit exceeded (1 MiB)");
            Datatype *baseType = decl->getBaseType();
            bool definedBase = std::find(parser.getLibraryAggregates().begin(),
                parser.getLibraryAggregates().end(), baseType) != parser.getLibraryAggregates().end()
                || (baseType->isEnumType() && before.find(baseType->getName()) == before.end());
            if (alias && !baseType->getName().empty() && !baseType->isCoreType()
                && definedBase
                && (before.find(baseType->getName()) == before.end()
                    || (incompleteBefore.count(baseType->getName()) && !baseType->isIncomplete()))
                && requestedSet.insert(baseType->getName()).second) {
                requested.push_back(baseType->getName());
                bounded(requested.size());
            }
            std::string name = alias ? decl->getIdentifier() : type->getName();
            if (name.empty()) throw ParseError("Top-level types require a name");
            if (alias) {
                if (arch->types->findByName(name) != nullptr) throw ParseError("Duplicate type name: " + name);
                type = arch->types->getTypedef(type, name, 0, 0);
            } else if (type->getMetatype() != TYPE_STRUCT && type->getMetatype() != TYPE_UNION && !type->isEnumType())
                throw ParseError("Expected a typedef, struct, union, or enum declaration");
            if (requestedSet.insert(name).second) requested.push_back(name);
            bounded(requested.size());
        }
        auto after = snapshot(arch->types);
        size_t namedCount = 0;
        std::set<Datatype *> graph;
        for (const auto &entry : after) {
            if (!entry.second->isCoreType()) {
                bounded(++namedCount);
                validateGraph(entry.second, graph);
            }
        }
        for (const auto &name : requested) {
            if (after.find(name) == after.end()) throw ParseError("Declared type was not retained: " + name);
        }
    }
    if (depth != 0 || start != tokens.size() || requested.empty()) throw ParseError("Unterminated type declaration");
    return requested;
}

inline std::string inventory(Architecture *arch, const std::vector<std::string> *names,
                             const std::map<Datatype *, int4> &packing) {
    Json json;
    json.append("[");
    size_t count = 0;
    auto write = [&](Datatype *type) {
        bounded(++count);
        if (count != 1) json.append(",");
        emit(json, type, packing);
    };
    if (names != nullptr) {
        for (const auto &name : *names) {
            Datatype *type = arch->types->findByName(name);
            if (type == nullptr) throw LowlevelError("Unknown named type: " + name);
            write(type);
        }
    } else {
        for (Datatype *type : arch->types->namedTypes()) {
            if (!type->isCoreType() && !type->getName().empty()) write(type);
        }
    }
    json.append("]");
    return json.take();
}

} // namespace type_library
} // namespace rampage
#endif
