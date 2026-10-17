#pragma once

#include "local_variables.hh"
#include "results.hh"
#include <algorithm>

namespace rampage {

struct NativeTypeHint {
    uint32_t kind;
    uint32_t index;
    NativeLocalOverride storage;
};

struct TypeHint {
    uint32_t kind;
    uint32_t index;
    LocalOverride storage;
};

inline std::vector<TypeHint> prepareTypeHints(ghidra::Architecture *arch,
                                             const NativeTypeHint *records, size_t count) {
    using namespace ghidra;
    if (count > 256) throw LowlevelError("Native type hint count exceeds 256");
    std::vector<TypeHint> hints;
    for (size_t i = 0; i < count; ++i) {
        const auto &record = records[i];
        if (record.kind > 2 || record.index >= 256 || record.storage.dataType == nullptr)
            throw LowlevelError("Invalid native type hint target");
        if (record.kind == 0) {
            auto locals = prepareLocals(arch, &record.storage, 1);
            auto meta = locals[0].type->getMetatype();
            if (meta == TYPE_STRUCT || meta == TYPE_UNION || meta == TYPE_ARRAY)
                throw LowlevelError("Unsupported aggregate native local hint");
            hints.push_back({record.kind, record.index, std::move(locals[0])});
            continue;
        }
        std::string declaration(record.storage.dataType);
        if (declaration.empty() || declaration.size() > 4096
            || declaration.find_first_of(";{}=()[]") != std::string::npos)
            throw LowlevelError("Type hint requires a bounded scalar or pointer abstract declaration");
        std::string name;
        std::istringstream input(localTypeDeclaration(arch, declaration) + " __rampage_type_hint");
        Datatype *type = parse_type(input, name, arch);
        input >> std::ws;
        if (name != "__rampage_type_hint" || !input.eof() || type->getSize() <= 0
            || type->getSize() > 1048576 || type->getMetatype() == TYPE_CODE
            || type->getMetatype() == TYPE_VOID || type->getMetatype() == TYPE_STRUCT
            || type->getMetatype() == TYPE_UNION || type->getMetatype() == TYPE_ARRAY)
            throw LowlevelError("Unsupported native type hint declaration");
        hints.push_back({record.kind, record.index, {Address(), type->getSize(), {}, "", type}});
    }
    return hints;
}

struct ResolvedTypeHint {
    LocalOverride storage;
    bool result;
    bool input;
};

struct CalleeTypeShape {
    std::string model;
    std::vector<ghidra::ParameterPieces> parameters;
    std::vector<bool> parameterHints;
    ghidra::ParameterPieces output;
    bool hasOutput;
    bool outputHinted;
};

struct TypeHintContext {
    std::vector<ResolvedTypeHint> own;
    const std::map<ghidra::uintb, CalleeTypeShape> *callees;
    size_t edges = 0;
    const std::vector<SavedLocal> *locals = nullptr;
};

inline bool scalarRegisterOutput(const ghidra::FuncProto &prototype) {
    using namespace ghidra;
    if (!prototype.hasModel()) return false;
    const auto *output = prototype.getOutput();
    auto meta = output->getType()->getMetatype();
    const auto &address = output->getAddress();
    return !output->isIndirectStorage() && !output->isHiddenReturn() && !address.isInvalid()
        && address.getSpace()->getType() == IPTR_PROCESSOR && output->getSize() > 0
        && (meta == TYPE_PTR || meta == TYPE_INT || meta == TYPE_UINT || meta == TYPE_BOOL || meta == TYPE_FLOAT)
        && !prototype.getArch()->translate->getRegisterName(address.getSpace(), address.getOffset(),
            output->getSize()).empty();
}

inline bool boundedRawReturnSuffix(ghidra::Funcdata *function, const ghidra::FuncCallSpecs *call) {
    using namespace ghidra;
    const auto &prototype = function->getFuncProto();
    if (!prototype.isOutputLocked() || prototype.numParams() > 256 || !scalarRegisterOutput(prototype)) return false;
    for (int4 i = 0; i < prototype.numParams(); ++i)
        if (prototype.getParam(i)->isHiddenReturn() || prototype.getParam(i)->isIndirectStorage()) return false;
    const auto *op = call->getOp();
    const auto *block = op == nullptr ? nullptr : op->getParent();
    if (block == nullptr || block->sizeOut() != 0) return false;
    const PcodeOp *normalReturn = nullptr;
    size_t returns = 0;
    for (auto iter = function->beginOp(CPUI_RETURN); iter != function->endOp(CPUI_RETURN); ++iter) {
        if (++returns > 256) return false;
        if ((*iter)->isDead() || (*iter)->getHaltType() != 0) continue;
        if (normalReturn != nullptr) return false;
        normalReturn = *iter;
    }
    if (normalReturn == nullptr || normalReturn->getParent() != block) return false;
    using Location = std::pair<Address, int4>;
    const auto *output = prototype.getOutput();
    std::vector<Location> values{{output->getAddress(), output->getSize()}};
    bool after = false;
    size_t visited = 0;
    for (auto iter = block->beginOp(); iter != block->endOp(); ++iter) {
        const auto *next = *iter;
        if (next == op) { after = true; continue; }
        if (!after || next->isDead()) continue;
        if (++visited > 256) return false;
        if (next == normalReturn)
            return std::find(values.begin(), values.end(), Location(output->getAddress(), output->getSize()))
                != values.end();
        auto code = next->code();
        if (code == CPUI_CALL || code == CPUI_CALLIND || code == CPUI_CALLOTHER || code == CPUI_BRANCH
            || code == CPUI_CBRANCH || code == CPUI_BRANCHIND || code == CPUI_RETURN) return false;
        const auto *written = next->getOut();
        if (written == nullptr) continue;
        bool copied = (code == CPUI_COPY || code == CPUI_CAST) && next->numInput() == 1
            && next->getIn(0)->getSize() == written->getSize()
            && std::find(values.begin(), values.end(), Location(next->getIn(0)->getAddr(), written->getSize()))
                != values.end();
        for (auto value = values.begin(); value != values.end();) {
            const auto &address = written->getAddr();
            bool overlap = address.getSpace() == value->first.getSpace()
                && (address.getOffset() >= value->first.getOffset()
                    ? address.getOffset() - value->first.getOffset() < uintb(value->second)
                    : value->first.getOffset() - address.getOffset() < uintb(written->getSize()));
            if (overlap) value = values.erase(value);
            else ++value;
        }
        if (copied) values.push_back({written->getAddr(), written->getSize()});
    }
    return false;
}

inline CalleeTypeShape collectCalleeTypeShape(ghidra::Funcdata *function, const std::vector<TypeHint> &hints,
                                             const std::vector<SavedLocal> &saved) {
    using namespace ghidra;
    const auto &prototype = function->getFuncProto();
    if (!prototype.hasModel() || prototype.isDotdotdot() || prototype.hasInputErrors()
        || prototype.hasOutputErrors() || prototype.numParams() > 256)
        throw LowlevelError("Unsupported native callee hint shape");
    CalleeTypeShape shape{};
    shape.model = prototype.getModelName();
    for (int4 i = 0; i < prototype.numParams(); ++i) {
        const auto *parameter = prototype.getParam(i);
        const auto *symbol = function->getScopeLocal()->getCategorySymbol(Symbol::function_parameter, i);
        const auto *entry = symbol == nullptr ? nullptr : symbol->getFirstWholeMap();
        auto meta = parameter->getType()->getMetatype();
        if (!results_detail::wholeMapping(symbol, entry) || parameter->isHiddenReturn()
            || parameter->isIndirectStorage() || parameter->getAddress().isInvalid()
            || parameter->getAddress().getSpace()->getType() != IPTR_PROCESSOR
            || entry->getAddr() != parameter->getAddress() || entry->getSize() != parameter->getSize()
            || meta == TYPE_STRUCT || meta == TYPE_UNION || meta == TYPE_ARRAY
            || function->getArch()->translate->getRegisterName(parameter->getAddress().getSpace(),
                parameter->getAddress().getOffset(), parameter->getSize()).empty())
            throw LowlevelError("Unsupported native callee hint: parameter needs one complete register mapping");
        ParameterPieces piece;
        piece.addr = parameter->getAddress();
        piece.type = parameter->getType();
        piece.flags = 0;
        shape.parameters.push_back(piece);
        bool hinted = analystTypeLocked(symbol, &saved);
        for (const auto &hint : hints)
            hinted |= (hint.kind == 1 && hint.index == uint32_t(i))
                || (hint.kind == 0 && matchesLocal(entry, hint.storage));
        shape.parameterHints.push_back(hinted);
    }
    const auto *output = prototype.getOutput();
    auto meta = output->getType()->getMetatype();
    shape.hasOutput = meta != TYPE_VOID;
    shape.outputHinted = output->isTypeLocked();
    for (const auto &hint : hints) shape.outputHinted |= hint.kind == 2;
    if (shape.hasOutput) {
        if (output->isIndirectStorage() || output->isHiddenReturn() || output->getAddress().isInvalid()
            || output->getAddress().getSpace()->getType() != IPTR_PROCESSOR
            || meta == TYPE_STRUCT || meta == TYPE_UNION || meta == TYPE_ARRAY
            || function->getArch()->translate->getRegisterName(output->getAddress().getSpace(),
                output->getAddress().getOffset(), output->getSize()).empty())
            throw LowlevelError("Unsupported native callee hint return storage");
        shape.output.addr = output->getAddress();
        shape.output.type = output->getType();
        shape.output.flags = 0;
    }
    // Check native ABI classification without applying a prototype or allocating replacement storage.
    PrototypePieces probe{};
    prototype.getPieces(probe);
    std::vector<ParameterPieces> classified;
    try {
        probe.model->assignParameterStorage(probe, classified, false);
    } catch (const LowlevelError &) {
        throw LowlevelError("Unsupported native callee hint ABI classification");
    }
    if (classified.size() != shape.parameters.size() + 1)
        throw LowlevelError("Unsupported native callee hint: ABI classification introduces hidden storage");
    for (size_t i = 0; i < classified.size(); ++i) {
        const auto &piece = classified[i];
        if ((piece.flags & (ParameterPieces::hiddenretparm | ParameterPieces::indirectstorage)) != 0)
            throw LowlevelError("Unsupported native callee hint hidden or indirect ABI classification");
        if (i == 0 && !shape.hasOutput) continue;
        const auto &actual = i == 0 ? shape.output : shape.parameters[i - 1];
        if (piece.addr != actual.addr || piece.type->getSize() != actual.type->getSize())
            throw LowlevelError("Unsupported native callee hint: hinted type changes the recovered ABI storage class");
    }
    return shape;
}

inline const CalleeTypeShape *calleeShape(const TypeHintContext &context, const ghidra::FuncCallSpecs *call) {
    if (context.callees == nullptr || call->getEntryAddress().isInvalid() || call->getOp() == nullptr
        || call->getOp()->code() != ghidra::CPUI_CALL || call->isDotdotdot()) return nullptr;
    auto found = context.callees->find(call->getEntryAddress().getOffset());
    return found == context.callees->end() ? nullptr : &found->second;
}

inline bool nativeCallInferenceHint(ghidra::Funcdata &function, ghidra::FuncCallSpecs *call,
                                    bool output, void *opaque) {
    using namespace ghidra;
    auto &context = *static_cast<TypeHintContext *>(opaque);
    const auto *shape = calleeShape(context, call);
    if (shape == nullptr) return false;
    if (!call->hasModel() || call->getModelName() != shape->model)
        throw LowlevelError("Unsupported native callee hint: calling-convention mismatch");
    if (output) {
        if (!shape->hasOutput || call->isOutputLocked()) return false;
        call->setOutput(shape->output);
        function.newVarnodeOut(shape->output.type->getSize(), shape->output.addr, call->getOp());
        return true;
    }
    if (call->isInputLocked()) return false;
    if (++context.edges > 256) throw LowlevelError("Native callee hint call edges exceed 256");
    auto *active = call->getActiveInput();
    if (active->getNumTrials() != 0 || call->getOp()->numInput() != 1)
        throw LowlevelError("Unsupported native callee hint: existing call input trials");
    call->clearUnlockedInput();
    for (size_t i = 0; i < shape->parameters.size(); ++i) {
        const auto &piece = shape->parameters[i];
        call->setParam(i, "", piece);
        active->registerTrial(piece.addr, piece.type->getSize());
        active->getTrial(i).markActive();
        function.opInsertInput(call->getOp(), function.newVarnode(piece.type->getSize(), piece.addr),
            call->getOp()->numInput());
    }
    return true;
}

inline bool analystCallValue(const ghidra::Varnode *value, const std::vector<SavedLocal> *saved) {
    if (value == nullptr) return false;
    const auto *source = results_detail::copySource(value);
    if (source == nullptr || source->isConstant()) return value->isTypeLock();
    const auto *high = source->getHigh();
    const auto *symbol = high == nullptr ? nullptr : high->getSymbol();
    return symbol == nullptr ? value->isTypeLock() : analystTypeLocked(symbol, saved);
}

inline void verifyCalleeTypeHints(ghidra::Funcdata *function, const TypeHintContext &context) {
    using namespace ghidra;
    for (int4 i = 0; i < function->numCalls(); ++i) {
        const auto *call = function->getCallSpecs(i);
        const auto *shape = calleeShape(context, call);
        if (shape == nullptr) continue;
        const auto *op = call->getOp();
        if (!call->isInputLocked()) {
            if (op->numInput() - 1 != int4(shape->parameters.size()))
                throw LowlevelError("Unsupported native callee hint: unlocked call shape was not retained");
            for (size_t slot = 0; slot < shape->parameters.size(); ++slot) {
                const auto *value = op->getIn(slot + 1);
                if (!shape->parameterHints[slot] || analystCallValue(value, context.locals)
                    || value->isConstant()) continue;
                if (value->getHigh()->getType() != shape->parameters[slot].type)
                    throw LowlevelError("Unsupported native callee hint: unlocked argument type was not retained");
            }
        }
        if (!call->isOutputLocked() && shape->hasOutput && shape->outputHinted) {
            const auto *value = op->getOut();
            if (!analystCallValue(value, context.locals)
                && (value == nullptr || value->getHigh()->getType() != shape->output.type))
                throw LowlevelError("Unsupported native callee hint: unlocked result type was not retained");
        }
    }
}

inline ghidra::Symbol *hintSymbol(ghidra::Funcdata *function, const LocalOverride &key) {
    using namespace ghidra;
    Symbol *found = nullptr;
    const auto *scope = function->getScopeLocal();
    for (auto iter = scope->begin(); iter != scope->end(); ++iter) {
        const auto *entry = *iter;
        Symbol *symbol = entry->getSymbol();
        if (!matchesLocal(entry, key) || !results_detail::isVariable(symbol)) continue;
        if (!results_detail::wholeMapping(symbol, entry) || found != nullptr)
            throw LowlevelError("Unsupported ambiguous or split native hint symbol");
        found = symbol;
    }
    if (found == nullptr) throw LowlevelError("Unsupported native hint: whole symbol mapping did not survive");
    return found;
}

inline std::vector<ResolvedTypeHint> resolveTypeHints(ghidra::Funcdata *function,
                                                     const std::vector<TypeHint> &hints,
                                                     const std::vector<SavedLocal> &saved) {
    using namespace ghidra;
    const auto &prototype = function->getFuncProto();
    if (prototype.isDotdotdot() || prototype.hasInputErrors() || prototype.hasOutputErrors())
        throw LowlevelError("Unsupported variadic or malformed native hint prototype");
    for (int4 i = 0; i < prototype.numParams(); ++i) {
        const auto *parameter = prototype.getParam(i);
        auto meta = parameter->getType()->getMetatype();
        if (parameter->isHiddenReturn() || parameter->isIndirectStorage() || parameter->getAddress().isInvalid()
            || parameter->getAddress().isJoin()
            || meta == TYPE_STRUCT || meta == TYPE_UNION || meta == TYPE_ARRAY)
            throw LowlevelError("Unsupported aggregate, hidden or indirect native hint parameter");
    }
    std::vector<ResolvedTypeHint> result;
    for (const auto &hint : hints) {
        LocalOverride key = hint.storage;
        if (hint.kind == 2) {
            const auto *output = prototype.getOutput();
            if (output->isTypeLocked()) continue;
            auto meta = output->getType()->getMetatype();
            if (output->isIndirectStorage() || output->getAddress().isInvalid() || output->getAddress().isJoin()
                || meta == TYPE_STRUCT || meta == TYPE_UNION || meta == TYPE_ARRAY
                || output->getSize() != key.type->getSize())
                throw LowlevelError("Unsupported native return hint width or storage");
            result.push_back({key, true, false});
            continue;
        }
        if (hint.kind == 1) {
            if (hint.index >= uint32_t(prototype.numParams()))
                throw LowlevelError("Native parameter hint index was not recovered");
            const auto *symbol = function->getScopeLocal()->getCategorySymbol(Symbol::function_parameter, hint.index);
            if (analystTypeLocked(symbol, &saved)) continue;
            const auto *entry = symbol == nullptr ? nullptr : symbol->getFirstWholeMap();
            if (!results_detail::wholeMapping(symbol, entry))
                throw LowlevelError("Unsupported native parameter hint mapping");
            key.address = entry->getAddr();
            key.size = entry->getSize();
            for (auto range = entry->getUseLimit().begin(); range != entry->getUseLimit().end(); ++range)
                key.ranges.push_back({range->getSpace(), range->getFirst(), range->getLast()});
        }
        Symbol *symbol = hintSymbol(function, key);
        if (analystTypeLocked(symbol, &saved)) continue;
        if (key.size != key.type->getSize())
            throw LowlevelError("Native type hint width differs from recovered whole symbol mapping");
        for (const auto &prior : result)
            if (!prior.result && prior.storage.address == key.address && prior.storage.size == key.size
                && matchesLocal(symbol->getMapEntry(0), prior.storage))
                throw LowlevelError("Duplicate native hint owning symbol");
        result.push_back({std::move(key), false, symbol->getCategory() == Symbol::function_parameter});
    }
    return result;
}

inline ghidra::Datatype *nativeInferenceHint(const ghidra::Funcdata &function,
                                            const ghidra::Varnode *value, void *context) {
    using namespace ghidra;
    const auto &state = *static_cast<const TypeHintContext *>(context);
    const auto &hints = state.own;
    for (const auto &hint : hints) {
        if (value->getSize() != hint.storage.type->getSize()) continue;
        if (hint.result) {
            size_t visited = 0;
            for (auto iter = function.beginOp(CPUI_RETURN); iter != function.endOp(CPUI_RETURN); ++iter) {
                if (++visited > 256) break;
                const auto *op = *iter;
                if (op->isDead() || op->getHaltType() != 0 || op->numInput() != 2) continue;
                const Varnode *node = op->getIn(1);
                for (size_t depth = 0; depth <= 16; ++depth) {
                    if (node == value) return hint.storage.type;
                    const auto *definition = node->getDef();
                    if (depth == 16 || definition == nullptr || definition->numInput() != 1
                        || (definition->code() != CPUI_COPY && definition->code() != CPUI_CAST)
                        || definition->getIn(0)->getSize() != value->getSize()) break;
                    node = definition->getIn(0);
                }
            }
            continue;
        }
        if (value->getAddr() != hint.storage.address || value->isConstant() || value->isAnnotation()) continue;
        if (hint.input && (!value->isInput()
            || function.findVarnodeInput(value->getSize(), value->getAddr()) != value)) continue;
        const auto *entry = value->getSymbolEntry();
        if (entry == nullptr) {
            // A recovered parameter maps uniquely to an incoming SSA value, never a later register reuse.
            if (!hint.input || !value->isInput()) continue;
        } else if (!results_detail::wholeMapping(entry->getSymbol(), entry)
            || !matchesLocal(entry, hint.storage)) continue;
        Address use = value->getUsePoint(function);
        bool matches = hint.storage.ranges.empty();
        for (const auto &range : hint.storage.ranges)
            if (use.getSpace() == range.space && use.getOffset() >= range.start && use.getOffset() <= range.end)
                matches = true;
        if (matches) return hint.storage.type;
    }
    // Caller values receive source-known callee context through the same unlocked native inference lattice.
    if (state.callees != nullptr) {
        size_t visited = 0;
        for (int4 i = 0; i < function.numCalls(); ++i) {
            if (++visited > 256) break;
            const auto *call = function.getCallSpecs(i);
            const auto *shape = calleeShape(state, call);
            if (shape == nullptr) continue;
            const auto *op = call->getOp();
            if (!call->isOutputLocked() && shape->hasOutput && value == op->getOut()
                && value->getSize() == shape->output.type->getSize()) {
                const auto &caller = function.getFuncProto();
                if (!shape->outputHinted && caller.isOutputLocked() && scalarRegisterOutput(caller)
                    && caller.getOutput()->getAddress() == shape->output.addr
                    && caller.getOutput()->getSize() == value->getSize()
                    && results_detail::directReturn(&function, value))
                    return caller.getOutputType();
                return shape->output.type;
            }
            if (call->isInputLocked() || op->numInput() - 1 != int4(shape->parameters.size())) continue;
            for (int4 slot = 1; slot < op->numInput(); ++slot)
                if (op->getIn(slot) == value && value->getSize() == shape->parameters[slot - 1].type->getSize())
                    return shape->parameters[slot - 1].type;
        }
    }
    return nullptr;
}

inline void verifyTypeHints(ghidra::Funcdata *function, const std::vector<ResolvedTypeHint> &hints,
                            const std::vector<SavedLocal> &saved) {
    for (const auto &hint : hints) {
        bool locked = hint.result ? function->getFuncProto().getOutput()->isTypeLocked()
            : analystTypeLocked(hintSymbol(function, hint.storage), &saved);
        const auto *type = hint.result ? function->getFuncProto().getOutputType()
            : hintSymbol(function, hint.storage)->getType();
        if (locked || type != hint.storage.type)
            throw ghidra::LowlevelError("Unsupported native soft hint: unlocked type was not retained by analysis");
    }
}

} // namespace rampage

namespace ghidra {

// Only this bounded regression probe can detach/restore symbol links; Varnode's mutators stay private.
class InferenceHintIdentityProbe {
public:
    static bool check(Funcdata &function, Varnode *input, Datatype *hint) {
        if (!function.isProcComplete() || input == nullptr || hint == nullptr
            || input->getSize() != hint->getSize()
            || function.findVarnodeInput(input->getSize(), input->getAddr()) != input) return false;
        SymbolEntry *original = input->getSymbolEntry();
        input->clearSymbolLinks();
        bool inputMatches;
        try {
            inputMatches = function.getInferenceHint(input) == hint;
        } catch (...) {
            if (original != nullptr) input->setSymbolEntry(original);
            throw;
        }
        if (original != nullptr) input->setSymbolEntry(original);
        PcodeOp *definition = function.newOp(2, function.getAddress() + 1);
        function.opSetOpcode(definition, CPUI_INT_ADD);
        function.opSetInput(definition, input, 0);
        function.opSetInput(definition, function.newConstant(input->getSize(), 1), 1);
        Varnode *later = function.newVarnodeOut(input->getSize(), input->getAddr(), definition);
        later->clearSymbolLinks();
        Datatype *before = later->getType();
        return inputMatches && function.getInferenceHint(later) == nullptr && later->getType() == before;
    }
};

} // namespace ghidra
