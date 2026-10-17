// SPDX-License-Identifier: Apache-2.0

#include <stdexcept>

#define KEEP __attribute__((noinline))

enum class Command { add, remove };
enum class Failure { capacity, insufficient };

class OperationError final : public std::runtime_error {
public:
    Failure reason;

    explicit OperationError(Failure value)
        : std::runtime_error(value == Failure::capacity ? "capacity exceeded" : "insufficient units"), reason(value) {}
};

class Processor {
public:
    virtual ~Processor() = default;
    virtual void apply(Command command, int units) = 0;
};

class Summary {
public:
    virtual ~Summary() = default;
    virtual int checksum() const = 0;
};

class Transaction {
    int &total_;
    unsigned &rollbacks_;
    int saved_;
    bool committed_ = false;

public:
    KEEP Transaction(int &total, unsigned &rollbacks) : total_(total), rollbacks_(rollbacks), saved_(total) {}

    KEEP ~Transaction() {
        if (!committed_) {
            total_ = saved_;
            ++rollbacks_;
        }
    }

    KEEP void commit() { committed_ = true; }
};

class Ledger final : public Processor, public Summary {
    int total_ = 0;
    int limit_;
    int factor_;
    unsigned accepted_ = 0;
    unsigned rollbacks_ = 0;

public:
    Ledger(int limit, int factor) : limit_(limit), factor_(factor) {}

    KEEP void apply(Command command, int units) override {
        Transaction transaction(total_, rollbacks_);
        const int amount = units * factor_;
        total_ += command == Command::add ? amount : -amount;
        if (total_ > limit_) {
            throw OperationError(Failure::capacity);
        }
        if (total_ < 0) {
            throw OperationError(Failure::insufficient);
        }
        ++accepted_;
        transaction.commit();
    }

    KEEP int checksum() const override {
        return total_ * 31 + static_cast<int>(accepted_ * 7 + rollbacks_);
    }
};

KEEP unsigned dispatch_commands(Processor &processor) {
    const struct {
        Command command;
        int units;
    } commands[] = {
        {Command::add, 5},
        {Command::remove, 2},
        {Command::add, 20},
        {Command::remove, 20},
        {Command::add, 1},
    };
    unsigned failures = 0;
    for (const auto &command : commands) {
        try {
            processor.apply(command.command, command.units);
        } catch (const OperationError &error) {
            failures |= error.reason == Failure::capacity ? 1u : 2u;
        }
    }
    return failures;
}

KEEP int read_summary(const Summary &summary) { return summary.checksum(); }

volatile int parity_cpp_checksum;
volatile unsigned parity_cpp_failures;

int main(int argc, char **) {
    Ledger ledger(40, argc > 1 ? 2 : 3);
    parity_cpp_failures = dispatch_commands(ledger);
    parity_cpp_checksum = read_summary(ledger);
    return 0;
}
