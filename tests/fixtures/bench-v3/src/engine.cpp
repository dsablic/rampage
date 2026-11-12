// SPDX-License-Identifier: Apache-2.0
// Suite v3, MSVC-ABI C++ on x86-64 Windows: an RTTI hierarchy with single and multiple inheritance, a vtable
// whose slot order is asked for, and a function with typed catch clauses. Every class the questions are about
// lives in namespace engine, so the C++ runtime's own polymorphic classes are told apart by namespace.
#include <cstdio>
#include <cstdlib>

namespace engine {

class Asset {
  public:
    explicit Asset(int id) : id_(id) {}
    virtual ~Asset() {}
    virtual int size() const = 0;
    virtual const char *kind() const = 0;
    virtual int load(int budget) { return budget - id_; }
    int id() const { return id_; }

  protected:
    int id_;
};

class Streamable {
  public:
    virtual ~Streamable() {}
    virtual int chunk(int index) const = 0;
    virtual int chunks() const { return 1; }
};

class Texture : public Asset {
  public:
    Texture(int id, int width, int height) : Asset(id), width_(width), height_(height) {}
    int size() const override { return width_ * height_ * 4; }
    const char *kind() const override { return "texture"; }
    int load(int budget) override { return budget - size() / 1024; }
    virtual int mip(int level) const { return (width_ >> level) * (height_ >> level); }
    virtual int stride() const { return width_ * 4 + 3; }

  protected:
    int width_, height_;
};

class Mesh : public Asset {
  public:
    Mesh(int id, int vertices) : Asset(id), vertices_(vertices) {}
    int size() const override { return vertices_ * 32; }
    const char *kind() const override { return "mesh"; }
    virtual int triangles() const { return vertices_ / 3; }

  protected:
    int vertices_;
};

class AnimatedMesh : public Mesh, public Streamable {
  public:
    AnimatedMesh(int id, int vertices, int frames) : Mesh(id, vertices), frames_(frames) {}
    int size() const override { return vertices_ * 32 * frames_; }
    const char *kind() const override { return "animated-mesh"; }
    int chunk(int index) const override { return index * vertices_; }
    int chunks() const override { return frames_; }

  private:
    int frames_;
};

class CubeTexture : public Texture {
  public:
    CubeTexture(int id, int edge) : Texture(id, edge, edge) {}
    int size() const override { return width_ * height_ * 24; }
    const char *kind() const override { return "cube-texture"; }
    int mip(int level) const override { return 6 * (width_ >> level) * (width_ >> level); }
};

class Cache : public Streamable {
  public:
    explicit Cache(int slots) : slots_(slots) {}
    int chunk(int index) const override { return index % slots_; }

  private:
    int slots_;
};

class EngineError {
  public:
    explicit EngineError(int code) : code_(code) {}
    virtual ~EngineError() {}
    virtual const char *what() const { return "engine error"; }
    int code() const { return code_; }

  private:
    int code_;
};

class LoadError : public EngineError {
  public:
    explicit LoadError(int code) : EngineError(code) {}
    const char *what() const override { return "load error"; }
};

class FormatError : public LoadError {
  public:
    explicit FormatError(int code) : LoadError(code) {}
    const char *what() const override { return "format error"; }
};

class BudgetError : public EngineError {
  public:
    explicit BudgetError(int code) : EngineError(code) {}
    const char *what() const override { return "budget error"; }
};

__declspec(noinline) Asset *make_asset(int which) {
    switch (which % 4) {
    case 0:
        return new Texture(which, 64, 32);
    case 1:
        return new Mesh(which, 300);
    case 2:
        return new AnimatedMesh(which, 120, 8);
    default:
        return new CubeTexture(which, 16);
    }
}

__declspec(noinline) int load_one(Asset *asset, int budget) {
    if (budget < 0) {
        throw BudgetError(budget);
    }
    if (asset->size() > 100000) {
        throw FormatError(asset->id());
    }
    if (asset->load(budget) < 0) {
        throw LoadError(asset->id());
    }
    return asset->size();
}

// One try block with two class-typed catch clauses.
__declspec(noinline) int load_checked(Asset *asset, int budget) {
    try {
        return load_one(asset, budget);
    } catch (const FormatError &error) {
        std::printf("%s %d\n", error.what(), error.code());
        return -2;
    } catch (const BudgetError &error) {
        std::printf("%s %d\n", error.what(), error.code());
        return -3;
    }
}

// Decoy: another try block that catches the base class.
__declspec(noinline) int load_any(Asset *asset, int budget) {
    try {
        return load_checked(asset, budget);
    } catch (const EngineError &error) {
        std::printf("%s\n", error.what());
        return -1;
    }
}

__declspec(noinline) int stream_total(const Streamable &stream) {
    int total = 0;
    for (int index = 0; index < stream.chunks(); index++) {
        total += stream.chunk(index);
    }
    return total;
}

} // namespace engine

int main(int argc, char **argv) {
    int which = argc > 1 ? std::atoi(argv[1]) : 2;
    int budget = argc > 2 ? std::atoi(argv[2]) : 50;
    engine::Asset *asset = engine::make_asset(which);
    engine::Cache cache(5);
    int total = engine::load_any(asset, budget) + engine::stream_total(cache);
    if (engine::Streamable *stream = dynamic_cast<engine::Streamable *>(asset)) {
        total += engine::stream_total(*stream);
    }
    if (engine::Texture *texture = dynamic_cast<engine::Texture *>(asset)) {
        total += texture->mip(1) + texture->stride();
    }
    std::printf("%s %d\n", asset->kind(), total);
    delete asset;
    return 0;
}
