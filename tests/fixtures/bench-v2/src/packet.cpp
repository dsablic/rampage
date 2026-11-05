// SPDX-License-Identifier: Apache-2.0
// Suite-v2 benchmark fixture: one polymorphic class whose data members have mixed sizes and padding, built
// stripped for arm64 macOS with RTTI. The task asks for the members' offsets and sizes; every member is read
// and written at its own width by an out-of-line virtual method.
#include <cstdint>
#include <cstdio>

class Packet {
public:
    Packet(uint8_t kind, uint16_t port, uint32_t length, double weight, int64_t stamp, char tag, uint32_t crc);
    virtual ~Packet();
    virtual uint64_t digest() const;
    virtual void update(uint8_t kind, uint16_t port, uint32_t length, double weight, int64_t stamp, char tag,
                        uint32_t crc);

private:
    uint8_t kind_;
    uint16_t port_;
    uint32_t length_;
    double weight_;
    int64_t stamp_;
    char tag_;
    uint32_t crc_;
};

Packet::Packet(uint8_t kind, uint16_t port, uint32_t length, double weight, int64_t stamp, char tag, uint32_t crc)
    : kind_(kind), port_(port), length_(length), weight_(weight), stamp_(stamp), tag_(tag), crc_(crc) {}

Packet::~Packet() {}

uint64_t Packet::digest() const {
    uint64_t value = kind_;
    value = value * 31 + port_;
    value = value * 31 + length_;
    value = value * 31 + static_cast<uint64_t>(weight_ * 1000.0);
    value = value * 31 + static_cast<uint64_t>(stamp_);
    value = value * 31 + static_cast<uint8_t>(tag_);
    value = value * 31 + crc_;
    return value;
}

void Packet::update(uint8_t kind, uint16_t port, uint32_t length, double weight, int64_t stamp, char tag,
                    uint32_t crc) {
    kind_ ^= kind;
    port_ += port;
    length_ -= length;
    weight_ *= weight;
    stamp_ += stamp;
    tag_ |= tag;
    crc_ ^= crc;
}

__attribute__((noinline)) Packet *make_packet(int seed) {
    return new Packet(static_cast<uint8_t>(seed), static_cast<uint16_t>(seed * 7), static_cast<uint32_t>(seed * 99),
                      seed * 0.5, seed * 100000LL, static_cast<char>('a' + seed), static_cast<uint32_t>(seed) * 2654435761u);
}

int main(int argc, char **argv) {
    (void)argv;
    Packet *packet = make_packet(argc);
    packet->update(1, 2, 3, 1.5, 4, 'z', 5);
    std::printf("%llu\n", static_cast<unsigned long long>(packet->digest()));
    delete packet;
    return 0;
}
