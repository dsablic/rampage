// SPDX-License-Identifier: Apache-2.0
// Suite-v2 benchmark fixture: vtable-only classes, built stripped for arm64 macOS with -fno-rtti, so no type
// names exist. The task asks for the slots of the vtable that make_codec installs, in order. Codec has no
// virtual destructor, so its vtable holds exactly its declared virtual functions, base slots first.
#include <cstdint>
#include <cstdio>

class Codec {
public:
    virtual int encode(const uint8_t *in, int n, uint8_t *out);
    virtual int decode(const uint8_t *in, int n, uint8_t *out);
    virtual void reset();

protected:
    uint8_t state_ = 0x5a;
};

class FastCodec : public Codec {
public:
    int decode(const uint8_t *in, int n, uint8_t *out) override;
    virtual void flush(uint8_t *out);

private:
    int pending_ = 0;
};

int Codec::encode(const uint8_t *in, int n, uint8_t *out) {
    for (int i = 0; i < n; i++) {
        out[i] = static_cast<uint8_t>(in[i] ^ state_);
        state_ = static_cast<uint8_t>(state_ * 5 + 1);
    }
    return n;
}

int Codec::decode(const uint8_t *in, int n, uint8_t *out) { return encode(in, n, out); }

void Codec::reset() { state_ = 0x5a; }

int FastCodec::decode(const uint8_t *in, int n, uint8_t *out) {
    for (int i = 0; i < n; i++) {
        out[i] = static_cast<uint8_t>(in[i] - state_);
    }
    pending_ += n;
    return n;
}

void FastCodec::flush(uint8_t *out) {
    out[0] = static_cast<uint8_t>(pending_);
    pending_ = 0;
}

__attribute__((noinline)) Codec *make_codec(int fast) {
    if (fast) {
        return new FastCodec;
    }
    return new Codec;
}

int main(int argc, char **argv) {
    (void)argv;
    Codec *codec = make_codec(argc > 1);
    uint8_t in[4] = {1, 2, 3, 4};
    uint8_t out[4];
    codec->encode(in, 4, out);
    codec->decode(out, 4, in);
    codec->reset();
    std::printf("%d\n", in[0]);
    return 0;
}
