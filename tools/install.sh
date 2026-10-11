#!/usr/bin/env bash
set -euo pipefail

root="$HOME/.local"
ui=false
root_seen=false
for argument in "$@"; do
    if [ "$argument" = "--ui" ]; then
        ui=true
    elif [ "$root_seen" = false ] && [[ "$argument" != --* ]]; then
        root="$argument"
        root_seen=true
    else
        echo 'Usage: tools/install.sh [ROOT] [--ui]' >&2
        exit 2
    fi
done
staging="$(mktemp -d)"
pending=false
cleanup() {
    rm -rf "$staging"
    if [ "$pending" = true ]; then
        rm -f "$root/bin/rampage-worker.new" "$root/bin/rampage.new"
        if [ "$ui" = true ]; then rm -f "$root/bin/rampage-ui.new"; fi
    fi
}
trap cleanup EXIT
if [ -x "$root/bin/rampage-ui" ]; then ui=true; fi
cargo install --path crates/rampage-worker --root "$staging" --locked
cargo install --path crates/rampage-cli --root "$staging" --locked
if [ "$ui" = true ]; then cargo install --path crates/rampage-ui --root "$staging" --locked; fi
mkdir -p "$root/bin"
for name in rampage rampage-worker; do
    if [ -e "$root/bin/$name.new" ] || [ -L "$root/bin/$name.new" ]; then
        echo "pending install file exists: $name.new" >&2
        exit 1
    fi
done
if [ "$ui" = true ] && { [ -e "$root/bin/rampage-ui.new" ] || [ -L "$root/bin/rampage-ui.new" ]; }; then
    echo 'pending UI install exists' >&2
    exit 1
fi
pending=true
cp "$staging/bin/rampage-worker" "$root/bin/rampage-worker.new"
cp "$staging/bin/rampage" "$root/bin/rampage.new"
if [ "$ui" = true ]; then cp "$staging/bin/rampage-ui" "$root/bin/rampage-ui.new"; fi
mv "$root/bin/rampage-worker.new" "$root/bin/rampage-worker"
mv "$root/bin/rampage.new" "$root/bin/rampage"
if [ "$ui" = true ]; then
    mv "$root/bin/rampage-ui.new" "$root/bin/rampage-ui"
fi
