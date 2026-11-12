//! The crate's integration tests build into this one test binary, one module per `tests/*.rs` file, so an edit
//! relinks one executable instead of one per file. Select a file's tests with `--test integration <file>::`.

mod architecture_slices;
mod archive;
mod buildinfo;
mod carve;
mod checked_images;
mod container;
mod debug;
mod debug_cpp_layouts;
mod debug_cpp_virtuals;
mod debug_layouts;
mod dotnet;
mod embedded;
mod gopclntab;
mod linkage;
mod load;
mod msvc_cpp;
mod objc;
mod pdb;
mod pdb_types;
mod raw;
mod snapshot;
