#!/usr/bin/env bash
set -euo pipefail

root="$HOME/.local"
ui=false
plugins=false
root_seen=false
for argument in "$@"; do
    if [ "$argument" = "--ui" ]; then
        ui=true
    elif [ "$argument" = "--plugins" ]; then
        plugins=true
    elif [ "$root_seen" = false ] && [[ "$argument" != --* ]]; then
        root="$argument"
        root_seen=true
    else
        echo 'Usage: tools/install.sh [ROOT] [--ui] [--plugins]' >&2
        exit 2
    fi
done
source_root="$PWD"
mkdir -p "$root/bin"
cd "$root/bin"
destination="$PWD"
if [ -x rampage-ui ]; then ui=true; fi
if [ -e rampage-plugin-worker ] || [ -L rampage-plugin-worker ]; then plugins=true; fi
names=(rampage-worker rampage)
if [ "$ui" = true ]; then names+=(rampage-ui); fi
if [ "$plugins" = true ]; then names+=(rampage-plugin-worker); fi

check_destination() {
    local directory="${1:-..}"
    local name
    if ! [ "$destination" -ef "$directory" ]; then
        echo 'Install destination namespace changed; refusing further publication.' >&2
        return 1
    fi
    for name in "${names[@]}"; do
        if [ -L "$directory/$name" ] || { [ -e "$directory/$name" ] && ! [ -f "$directory/$name" ]; }; then
            echo "Unexpected install destination preserved: $destination/$name" >&2
            return 1
        fi
    done
}
check_destination .
staging="$(mktemp -d "$destination/.rampage-install.XXXXXXXX")"
published=''
attempted=''
complete=false
report() {
    local status=$?
    trap - EXIT
    if [ "$complete" = false ]; then
        echo 'Install incomplete; files are published separately, with no rollback.' >&2
        if [ -n "$published" ]; then
            printf 'Confirmed publication before failure: %s\n' "$published" >&2
        fi
        if [ -n "$attempted" ]; then
            echo "Publication may have changed $attempted; inspect the destination before retrying." >&2
        fi
    fi
    echo "Private staging retained (including Cargo metadata); original path: $staging" >&2
    echo 'If the namespace changed, this original path may no longer identify the retained directory.' >&2
    echo 'No staging or .new paths are automatically deleted; inspect retained files before removing them.' >&2
    exit "$status"
}
trap report EXIT
cd "$staging"
mkdir previous identity-new identity-previous
export CARGO_BUILD_JOBS=2
cargo install --path "$source_root/crates/rampage-worker" --root . --locked
cargo install --path "$source_root/crates/rampage-cli" --root . --locked
if [ "$ui" = true ]; then cargo install --path "$source_root/crates/rampage-ui" --root . --locked; fi
if [ "$plugins" = true ]; then
    cargo install --path "$source_root/crates/rampage-plugin-worker" --root . --locked
fi
for name in "${names[@]}"; do
    check_destination
    if ! [ "$staging" -ef . ] || [ -L bin ] || ! [ -d bin ]; then
        echo 'Private staging namespace changed; retained without cleanup.' >&2
        exit 1
    fi
    if [ -L "bin/$name" ] || ! [ -f "bin/$name" ] || ! [ -x "bin/$name" ]; then
        echo "Missing or unexpected staged executable: $name" >&2
        exit 1
    fi
    if [ -L identity-new ] || ! [ -d identity-new ] ||
        [ -L identity-previous ] || ! [ -d identity-previous ]; then
        echo 'Unexpected identity directory preserved; refusing publication.' >&2
        exit 1
    fi
    # Hard links pin identities without relying on BSD /dev/fd stat semantics.
    ln -P "bin/$name" identity-new/
    if [ -L "identity-new/$name" ] || ! [ -f "identity-new/$name" ] ||
        ! [ -x "identity-new/$name" ] || ! [ "bin/$name" -ef "identity-new/$name" ]; then
        echo "Staged executable identity is uncertain: $name" >&2
        exit 1
    fi
    attempted="$name"
    if [ -e "../$name" ]; then
        if [ -L previous ] || ! [ -d previous ]; then
            echo 'Unexpected backup directory preserved; refusing replacement.' >&2
            exit 1
        fi
        if [ -e "previous/$name" ] || [ -L "previous/$name" ]; then
            echo "Unexpected backup occupant preserved: $name; installed executable unchanged." >&2
            exit 1
        fi
        ln -P "../$name" identity-previous/
        if [ -L "identity-previous/$name" ] || ! [ -f "identity-previous/$name" ]; then
            echo "Previous destination identity is uncertain: $name; inspect retained staging." >&2
            exit 1
        fi
        # BSD mv -n alone does not protect a pre-existing dangling backup symlink.
        mv -n "../$name" previous/
        if [ -L "previous/$name" ] || ! [ "previous/$name" -ef "identity-previous/$name" ]; then
            echo "Previous destination identity is uncertain: $name; inspect retained staging." >&2
            exit 1
        fi
        check_destination
    fi
    # The directory operand and exclusive link preserve a newly arrived file, symlink or directory.
    ln -P "identity-new/$name" ..
    check_destination
    if ! [ "../$name" -ef "identity-new/$name" ]; then
        echo "Publication identity is uncertain: $name" >&2
        exit 1
    fi
    if ! [ "$staging" -ef . ]; then
        echo 'Private staging namespace changed during publication; inspect both namespaces.' >&2
        exit 1
    fi
    published="${published:+$published }$name"
    attempted=''
done
complete=true
printf 'Installed from this source tree (separate file publications): %s\n' "${names[*]}"
