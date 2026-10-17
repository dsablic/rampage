#pragma once

#include "prettyprint.hh"
#include "funcdata.hh"
#include "op.hh"

#include <cstddef>
#include <utility>

namespace rampage {

struct Token {
    std::string text;
    std::string kind;
    uint64_t address;
    bool hasAddress;
    std::size_t start = 0;
    std::size_t end = 0;
    bool hasSpan = false;
};

inline void checkTokenLimit(const std::vector<Token> &tokens) {
    constexpr std::size_t tokenLimit = 262144;
    if (tokens.size() >= tokenLimit) throw ghidra::LowlevelError("Decompiler token limit exceeded");
}

class TokenEmitter : public ghidra::EmitNoMarkup {
    std::vector<Token> &tokens;
    template <typename EmitToken>
    void record(Token token, EmitToken emit) {
        checkTokenLimit(tokens);
        auto *stream = getOutputStream();
        const auto start = stream->tellp();
        emit();
        const auto end = stream->tellp();
        if (start >= std::streampos(0) && end >= start) {
            token.start = static_cast<std::size_t>(static_cast<std::streamoff>(start));
            token.end = static_cast<std::size_t>(static_cast<std::streamoff>(end));
            token.hasSpan = true;
        }
        tokens.push_back(std::move(token));
    }
public:
    explicit TokenEmitter(std::vector<Token> &values) : tokens(values) {}
    void tagVariable(const std::string &text, syntax_highlight color, const ghidra::Varnode *vn,
                     const ghidra::PcodeOp *op) override {
        record({text, "variable", op == nullptr ? 0 : op->getAddr().getOffset(), op != nullptr}, [&] {
            EmitNoMarkup::tagVariable(text, color, vn, op);
        });
    }
    void tagOp(const std::string &text, syntax_highlight color, const ghidra::PcodeOp *op) override {
        record({text, "operator", op == nullptr ? 0 : op->getAddr().getOffset(), op != nullptr}, [&] {
            EmitNoMarkup::tagOp(text, color, op);
        });
    }
    void tagFuncName(const std::string &text, syntax_highlight color, const ghidra::Funcdata *function,
                     const ghidra::PcodeOp *op) override {
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
        record(std::move(token), [&] { EmitNoMarkup::tagFuncName(text, color, function, op); });
    }
    void tagType(const std::string &text, syntax_highlight color, const ghidra::Datatype *type) override {
        record({text, "type", 0, false}, [&] { EmitNoMarkup::tagType(text, color, type); });
    }
    void tagField(const std::string &text, syntax_highlight color, const ghidra::Datatype *type,
                  ghidra::int4 offset, const ghidra::PcodeOp *op) override {
        record({text, "field", op == nullptr ? 0 : op->getAddr().getOffset(), op != nullptr}, [&] {
            EmitNoMarkup::tagField(text, color, type, offset, op);
        });
    }
};

inline void collectFlow(ghidra::Funcdata *function, std::vector<Token> &tokens) {
    const auto &blocks = function->getBasicBlocks();
    for (ghidra::int4 i = 0; i < blocks.getSize(); ++i) {
        checkTokenLimit(tokens);
        const auto *block = blocks.getBlock(i);
        tokens.push_back({std::to_string(block->getIndex()), "block", block->getStart().getOffset(), true});
    }
    for (ghidra::int4 i = 0; i < function->numCalls(); ++i) {
        checkTokenLimit(tokens);
        auto *call = function->getCallSpecs(i);
        if (!call->getEntryAddress().isInvalid())
            tokens.push_back({call->getName(), "call", call->getEntryAddress().getOffset(), true});
    }
    for (ghidra::int4 i = 0; i < function->numJumpTables(); ++i) {
        auto *table = function->getJumpTable(i);
        for (ghidra::int4 entry = 0; entry < table->numEntries(); ++entry) {
            checkTokenLimit(tokens);
            auto address = table->getAddressByIndex(entry).getOffset();
            tokens.push_back({std::to_string(entry), "switch_target", address, true});
        }
    }
}

}
