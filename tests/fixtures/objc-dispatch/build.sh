#!/usr/bin/env bash
# Builds the Objective-C message-send fixtures (Apple clang, macOS): arm64 (chained fixups, relative method
# lists, __objc_stubs selector stubs) and x86_64 (calls through the objc_msgSend GOT slot), each unstripped and
# stripped. arm64 links with the default category merging (the Debug category joins Shape's method list); x86_64
# keeps the category separate (-no_objc_category_merging). The expected resolution of every send is in
# crates/rampage-analysis/tests/objc_dispatch.rs.
set -euo pipefail
cd "$(dirname "$0")"
out=../bin
flags=(-O1 -fobjc-arc -framework Foundation)
clang -arch arm64 "${flags[@]}" -o "$out/objc-dispatch-arm64.macho" dispatch.m
clang -arch x86_64 "${flags[@]}" -Wl,-no_objc_category_merging -o "$out/objc-dispatch-x64.macho" dispatch.m
strip -o "$out/objc-dispatch-arm64-stripped.macho" "$out/objc-dispatch-arm64.macho"
strip -o "$out/objc-dispatch-x64-stripped.macho" "$out/objc-dispatch-x64.macho"
