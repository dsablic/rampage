#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ ${1:-} != --check || $# -lt 2 ]]; then
  echo 'usage: bash tools/ci/function-inventory-oracle.sh --check command [arguments...]' >&2
  exit 2
fi
shift
if [[ -z ${TMPDIR:-} || ! -d $TMPDIR ]]; then
  echo 'set TMPDIR to an approved private temporary directory' >&2
  exit 2
fi
scratch=$(mktemp -d "$TMPDIR/rampage-function-inventory.XXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
chmod 700 "$scratch"
sysroot=${RUST_SYSROOT:-$(rustc --print sysroot)}
host=${RUST_HOST:-$(rustc --version --verbose | sed -n 's/^host: //p')}
lld="$sysroot/lib/rustlib/$host/bin/rust-lld"
test -x "$lld"

# Volatile input and accumulator preserve branches, loops and all direct calls at O1.
awk 'BEGIN {
  print "volatile unsigned long inventory_input = 19, inventory_output;"
  for (i = 0; i < 2300; i++) {
    printf "__attribute__((noinline)) unsigned long inventory_%04d(unsigned long x) {\n", i
    printf "  for (unsigned long j = 0; j < (inventory_input & 7) + 2; ++j) {\n"
    printf "    if ((x ^ j) & 1) x = x * 3 + %d; else x = (x >> 1) ^ %d;\n", i + 1, i + 17
    print "  } return x; }"
  }
  print "void _start(void) { unsigned long x = inventory_input;"
  for (i = 0; i < 2300; i++) printf "  x = inventory_%04d(x);\n", i
  print "  inventory_output = x; for (;;) {} }"
}' > "$scratch/generated.c"
cat > "$scratch/hello.c" <<'EOF'
volatile unsigned long hello_input = 3, hello_output;
__attribute__((noinline)) unsigned long hello(unsigned long x) {
  for (unsigned long j = 0; j < hello_input; ++j) {
    if (x & 1) x = x * 3 + 1; else x >>= 1;
  }
  return x;
}
void _start(void) { hello_output = hello(hello_input); for (;;) {} }
EOF

for fixture in generated hello; do
  clang --target=x86_64-unknown-linux-gnu -ffreestanding -fno-stack-protector -fno-builtin \
    -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-pic -fno-pie -g0 -O1 \
    -c "$scratch/$fixture.c" -o "$scratch/$fixture.o"
  env DYLD_LIBRARY_PATH="$sysroot/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" \
    "$lld" -flavor gnu -static --build-id=none -e _start -o "$scratch/$fixture.elf" "$scratch/$fixture.o"
done

# The supplied command may inspect these owned files; neither ELF is ever executed by this recipe.
export RAMPAGE_FUNCTION_INVENTORY_FIXTURES="$scratch"
"$@"
