#!/usr/bin/env bash
set -euo pipefail

usage='Usage: tools/install.sh [ROOT] [--ui] [--plugins] [--archive FILE.tar.gz]
       tools/install.sh [ROOT] --uninstall

Installs rampage and rampage-worker (plus rampage-ui with --ui, rampage-plugin-worker with --plugins) into ROOT/bin
(default ~/.local/bin), from this source tree or, with --archive, from a prebuilt release archive. Source builds use
Cargo'"'"'s default job count; set CARGO_BUILD_JOBS to override it. --uninstall removes those programs from ROOT/bin.'
root="$HOME/.local"
ui=false
plugins=false
uninstall=false
archive=''
expect_archive=false
root_seen=false
for argument in "$@"; do
    if [ "$expect_archive" = true ]; then
        archive="$argument"
        expect_archive=false
    elif [ "$argument" = "--ui" ]; then
        ui=true
    elif [ "$argument" = "--plugins" ]; then
        plugins=true
    elif [ "$argument" = "--uninstall" ]; then
        uninstall=true
    elif [ "$argument" = "--archive" ]; then
        expect_archive=true
    elif [ "$argument" = "--help" ] || [ "$argument" = "-h" ]; then
        printf '%s\n' "$usage"
        exit 0
    elif [ "$root_seen" = false ] && [[ "$argument" != --* ]]; then
        root="$argument"
        root_seen=true
    else
        printf '%s\n' "$usage" >&2
        exit 2
    fi
done
if [ "$expect_archive" = true ] || { [ "$uninstall" = true ] &&
    { [ "$ui" = true ] || [ "$plugins" = true ] || [ -n "$archive" ]; }; }; then
    printf '%s\n' "$usage" >&2
    exit 2
fi
# The source tree is the checkout holding this script, so the installer works from any directory.
source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ -n "$archive" ]; then
    if [ "$plugins" = true ]; then
        echo 'Release archives do not include rampage-plugin-worker; install it from source with --plugins.' >&2
        exit 2
    fi
    if ! [ -f "$archive" ] || [ -L "$archive" ]; then
        echo "Archive is not a regular file: $archive" >&2
        exit 2
    fi
    archive="$(cd "$(dirname "$archive")" && pwd)/$(basename "$archive")"
elif [ "$uninstall" = false ] && ! [ -f "$source_root/crates/rampage-cli/Cargo.toml" ]; then
    echo "No rampage source tree at $source_root; run the tools/install.sh of a rampage checkout." >&2
    exit 2
fi

all_names=(rampage-worker rampage rampage-ui rampage-plugin-worker)
if [ "$uninstall" = true ]; then
    if ! [ -d "$root/bin" ]; then
        echo "Nothing to uninstall: $root/bin does not exist."
        exit 0
    fi
    cd "$root/bin"
    removed=''
    preserved=false
    for name in "${all_names[@]}"; do
        if [ -L "$name" ] || { [ -e "$name" ] && ! [ -f "$name" ]; }; then
            echo "Not a regular file; preserved: $PWD/$name" >&2
            preserved=true
        elif [ -f "$name" ]; then
            rm -f -- "./$name"
            removed="${removed:+$removed }$name"
        fi
    done
    echo "Removed from $PWD: ${removed:-nothing}"
    for leftover in .rampage-install.*; do
        if [ -e "$leftover" ]; then
            echo "Retained staging from an earlier failed install (inspect, then remove): $PWD/$leftover" >&2
        fi
    done
    if [ "$preserved" = true ]; then exit 1; fi
    exit 0
fi

mkdir -p "$root/bin"
cd "$root/bin"
destination="$PWD"
if [ -x rampage-ui ]; then ui=true; fi
if [ -e rampage-plugin-worker ] || [ -L rampage-plugin-worker ]; then plugins=true; fi
if [ -n "$archive" ] && [ "$plugins" = true ]; then
    echo "Release archives do not include rampage-plugin-worker, and an installed one would no longer match." >&2
    echo "Install from source with --plugins, or remove $destination/rampage-plugin-worker first." >&2
    exit 2
fi
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
cleaned=false
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
    if [ "$cleaned" = false ]; then
        echo "Private staging retained (including Cargo metadata); original path: $staging" >&2
        echo 'If the namespace changed, this original path may no longer identify the retained directory.' >&2
        echo 'No staging or .new paths are automatically deleted; inspect retained files before removing them.' >&2
    fi
    exit "$status"
}
# After a confirmed install, removes the staging directory only if it holds nothing but what this script created
# (staged and previous executables, their identity links and Cargo metadata). Anything else keeps it all retained.
expected_staging_entry() {
    local path=$1
    local directory
    local name
    case "$path" in
        ./bin | ./previous | ./identity-new | ./identity-previous | ./.crates.toml | ./.crates2.json) return 0 ;;
    esac
    for directory in bin previous identity-new identity-previous; do
        for name in "${names[@]}"; do
            if [ "$path" = "./$directory/$name" ] && [ -f "$path" ] && ! [ -L "$path" ]; then return 0; fi
        done
    done
    return 1
}
clean_staging() {
    local path
    local directory
    local name
    if ! [ "$staging" -ef . ]; then return 1; fi
    for directory in bin previous identity-new identity-previous; do
        if [ -L "$directory" ] || ! [ -d "$directory" ]; then return 1; fi
    done
    while IFS= read -r path; do
        expected_staging_entry "$path" || return 1
    done < <(find . -mindepth 1)
    for directory in bin previous identity-new identity-previous; do
        for name in "${names[@]}"; do rm -f -- "./$directory/$name"; done
        rmdir -- "$directory" || return 1
    done
    rm -f -- ./.crates.toml ./.crates2.json
    cd ..
    if ! [ "$destination" -ef . ]; then return 1; fi
    rmdir -- "${staging##*/}"
}
trap report EXIT
cd "$staging"
mkdir previous identity-new identity-previous
if [ -n "$archive" ]; then
    if [ -f "$archive.sha256" ]; then
        (
            cd "$(dirname "$archive")"
            if command -v sha256sum > /dev/null; then
                sha256sum --check --strict "$(basename "$archive").sha256"
            else
                shasum -a 256 --check "$(basename "$archive").sha256"
            fi
        )
    else
        echo "No $archive.sha256 next to the archive; its checksum was not verified." >&2
    fi
    mkdir unpack bin
    tar -xzf "$archive" -C unpack
    for name in "${names[@]}"; do
        found=(unpack/*/bin/"$name")
        if [ "${#found[@]}" -ne 1 ] || [ -L "${found[0]}" ] || ! [ -f "${found[0]}" ]; then
            echo "The archive has no single regular bin/$name." >&2
            exit 1
        fi
        mv "${found[0]}" "bin/$name"
        chmod 0755 "bin/$name"
    done
    rm -rf -- ./unpack
else
    echo "Building ${names[*]} from $source_root with the release profile (ThinLTO, one codegen unit)." >&2
    echo 'A cold build of the CLI, worker and UI took 23 minutes on a 2-vCPU Linux CI runner; more cores finish sooner.' >&2
    cargo install --path "$source_root/crates/rampage-worker" --root . --locked
    cargo install --path "$source_root/crates/rampage-cli" --root . --locked
    if [ "$ui" = true ]; then cargo install --path "$source_root/crates/rampage-ui" --root . --locked; fi
    if [ "$plugins" = true ]; then
        cargo install --path "$source_root/crates/rampage-plugin-worker" --root . --locked
    fi
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
if clean_staging; then
    cleaned=true
else
    echo 'Staging held unexpected entries or moved, so it was not removed.' >&2
fi
if [ -n "$archive" ]; then
    printf 'Installed from %s (separate file publications): %s\n' "$archive" "${names[*]}"
else
    printf 'Installed from this source tree (separate file publications): %s\n' "${names[*]}"
fi
printf 'Remove them with: %s %q --uninstall\n' "$source_root/tools/install.sh" "${destination%/bin}"
