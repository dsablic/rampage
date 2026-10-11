#pragma once

#include "prettyprint.hh"
#include "funcdata.hh"
#include "op.hh"

namespace rampage {

struct Token {
    std::string text;
    std::string kind;
    uint64_t address;
    bool hasAddress;
};

class TokenEmitter : public ghidra::EmitNoMarkup {
    std::vector<Token> &tokens;
    void record(const std::string &text, const std::string &kind, const ghidra::PcodeOp *op) {
        if (tokens.size() >= 262144) throw ghidra::LowlevelError("Decompiler token limit exceeded");
        tokens.push_back({text, kind, op == nullptr ? 0 : op->getAddr().getOffset(), op != nullptr});
    }
public:
    explicit TokenEmitter(std::vector<Token> &values) : tokens(values) {}
    void tagVariable(const std::string &text, syntax_highlight color, const ghidra::Varnode *vn,
                     const ghidra::PcodeOp *op) override {
        record(text, "variable", op); EmitNoMarkup::tagVariable(text, color, vn, op);
    }
    void tagOp(const std::string &text, syntax_highlight color, const ghidra::PcodeOp *op) override {
        record(text, "operator", op); EmitNoMarkup::tagOp(text, color, op);
    }
    void tagFuncName(const std::string &text, syntax_highlight color, const ghidra::Funcdata *function,
                     const ghidra::PcodeOp *op) override {
        if (tokens.size() >= 262144) throw ghidra::LowlevelError("Decompiler token limit exceeded");
        Token token{text, "function", 0, false};
        if (function != nullptr) { token.address = function->getAddress().getOffset(); token.hasAddress = true; }
        else if (op != nullptr && op->code() == ghidra::CPUI_CALL) {
            const ghidra::Varnode *input = op->getIn(0);
            token.address = input->getSpace()->getType() == ghidra::IPTR_FSPEC
                ? ghidra::FuncCallSpecs::getFspecFromConst(input->getAddr())->getEntryAddress().getOffset()
                : input->getOffset();
            token.hasAddress = true;
        }
        else if (op != nullptr) { token.address = op->getAddr().getOffset(); token.hasAddress = true; }
        tokens.push_back(token); EmitNoMarkup::tagFuncName(text, color, function, op);
    }
    void tagType(const std::string &text, syntax_highlight color, const ghidra::Datatype *type) override {
        if (tokens.size() >= 262144) throw ghidra::LowlevelError("Decompiler token limit exceeded");
        tokens.push_back({text, "type", 0, false}); EmitNoMarkup::tagType(text, color, type);
    }
};

inline void collectFlow(ghidra::Funcdata *function, std::vector<Token> &tokens) {
    const auto &blocks = function->getBasicBlocks();
    for (ghidra::int4 i = 0; i < blocks.getSize(); ++i) {
        if (tokens.size() >= 262144) throw ghidra::LowlevelError("Decompiler token limit exceeded");
        const auto *block = blocks.getBlock(i);
        tokens.push_back({std::to_string(block->getIndex()), "block", block->getStart().getOffset(), true});
    }
    for (ghidra::int4 i = 0; i < function->numCalls(); ++i) {
        if (tokens.size() >= 262144) throw ghidra::LowlevelError("Decompiler token limit exceeded");
        auto *call = function->getCallSpecs(i);
        if (!call->getEntryAddress().isInvalid())
            tokens.push_back({call->getName(), "call", call->getEntryAddress().getOffset(), true});
    }
    for (ghidra::int4 i = 0; i < function->numJumpTables(); ++i) {
        auto *table = function->getJumpTable(i);
        for (ghidra::int4 entry = 0; entry < table->numEntries(); ++entry) {
            if (tokens.size() >= 262144) throw ghidra::LowlevelError("Decompiler token limit exceeded");
            auto address = table->getAddressByIndex(entry).getOffset();
            tokens.push_back({std::to_string(entry), "switch_target", address, true});
        }
    }
}

}
