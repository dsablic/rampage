#!/usr/bin/env bash
set -euo pipefail

# All commands under test see only fixture roots and fake Cargo; no packages are compiled or executed.
repository="$(cd "$(dirname "$0")/.." && pwd)"
fixture="$(mktemp -d "${TMPDIR:-/tmp}/rampage-install-test.XXXXXXXX")"
trap 'rm -rf "$fixture"' EXIT
real_mv="$(command -v mv)"
real_ln="$(command -v ln)"
export real_mv real_ln
mkdir "$fixture/hooks"
cat > "$fixture/hooks/cargo" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -ne 6 ] || [ "$1" != install ] || [ "$2" != --path ] ||
    [ "$4" != --root ] || [ "$5" != . ] || [ "$6" != --locked ]; then
    printf 'Unexpected fake Cargo arguments: ' >&2
    printf '%q ' "$@" >&2
    printf '\n' >&2
    exit 90
fi
if [ "$CARGO_BUILD_JOBS" != 2 ]; then
    echo "Unexpected Cargo job count: $CARGO_BUILD_JOBS" >&2
    exit 90
fi
package="${3##*/}"
printf '%s\n' "$package" >> "$case_root/cargo.log"
printf '%s\n' "$PWD" > "$case_root/staging.path"
if [ "$mode" = build_failure ] && [ "$package" = rampage-cli ]; then exit 41; fi
name="$package"
if [ "$package" = rampage-cli ]; then name=rampage; fi
mkdir -p bin
printf '#!/bin/sh\nexit 91\n# new %s\n' "$name" > "bin/$name"
chmod +x "bin/$name"
printf 'fixture metadata\n' > .crates.toml
if [ "$package" = rampage-cli ]; then
    if [ "$mode" = stage_swap ]; then
        "$real_mv" "$PWD" "$PWD.moved"
        mkdir "$PWD"
        printf 'unrelated stage occupant\n' > "$PWD/sentinel"
    elif [ "$mode" = stage_occupant ]; then
        printf 'unrelated stage occupant\n' > sentinel
    elif [ "$mode" = backup_occupant ]; then
        printf 'unrelated backup occupant\n' > previous/rampage-worker
    elif [ "$mode" = backup_directory ]; then
        mkdir previous/rampage-worker
        printf 'unrelated backup directory\n' > previous/rampage-worker/sentinel
    elif [ "$mode" = backup_live_symlink ]; then
        "$real_ln" -s "$case_root/victim" previous/rampage-worker
    elif [ "$mode" = backup_dangling_symlink ]; then
        "$real_ln" -s "$case_root/missing-backup-target" previous/rampage-worker
    elif [ "$mode" = previous_directory_symlink ]; then
        "$real_mv" previous "$case_root/original-previous"
        mkdir "$case_root/alternate-previous"
        printf 'unrelated previous directory\n' > "$case_root/alternate-previous/sentinel"
        "$real_ln" -s "$case_root/alternate-previous" previous
    elif [ "$mode" = staged_symlink ]; then
        mkdir "$case_root/alternate-bin"
        printf 'unrelated staged target\n' > "$case_root/alternate-bin/sentinel"
        "$real_mv" bin "$case_root/original-staged-bin"
        "$real_ln" -s "$case_root/alternate-bin" bin
    elif [ "$mode" = destination_symlink ]; then
        ln -s "$case_root/victim" "$install_bin/rampage"
    fi
fi
SH
cat > "$fixture/hooks/mv" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$2" >> "$case_root/moves.log"
if [ "$mode" = move_failure ] && [[ "$2" = */rampage ]]; then exit 42; fi
if [ "$mode" = move_failure_after ] && [[ "$2" = */rampage ]]; then
    "$real_mv" "$@"
    exit 43
fi
if [ "$mode" = false_success ]; then exit 0; fi
if [ "$mode" = destination_swap ]; then
    "$real_mv" "$install_bin" "$install_bin.moved"
    mkdir "$install_bin"
    printf 'unrelated destination occupant\n' > "$install_bin/sentinel"
elif [ "$mode" = existing_late_symlink ]; then
    "$real_mv" "$2" "$case_root/displaced-worker"
    "$real_ln" -s "$case_root/victim" "$2"
fi
"$real_mv" "$@"
SH
cat > "$fixture/hooks/ln" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -eq 3 ] && [ "$1" = -P ] && [ "$3" = .. ]; then
    if [ "$mode" = link_false_success ]; then exit 0; fi
    if [ "$mode" = late_occupant ]; then
        "$real_ln" -s "$case_root/victim" "$3/${2##*/}"
    elif [ "$mode" = late_directory ]; then
        mkdir "$3/${2##*/}"
        printf 'unrelated directory\n' > "$3/${2##*/}/sentinel"
    elif [ "$mode" = link_destination_swap ]; then
        "$real_mv" "$install_bin" "$install_bin.moved"
        mkdir "$install_bin"
        printf 'unrelated destination occupant\n' > "$install_bin/sentinel"
    elif [ "$mode" = link_stage_swap ]; then
        "$real_mv" "$PWD" "$PWD.moved"
        mkdir "$PWD"
        printf 'unrelated stage occupant\n' > "$PWD/sentinel"
    fi
    if [ "$mode" = link_failure_after ]; then
        "$real_ln" "$@"
        exit 44
    fi
fi
"$real_ln" "$@"
SH
chmod +x "$fixture/hooks/"*

fail() { echo "FAIL: $case_name: $*" >&2; exit 1; }
finish() {
    local result=$?
    local output
    trap - EXIT
    if [ "$result" -ne 0 ]; then
        printf 'Failed case: %s; owned fixture: %s\n' "${case_name:-setup}" "$fixture" >&2
        for output in stderr stdout cargo.log moves.log staging.path; do
            if [ -n "${case_root:-}" ] && [ -f "$case_root/$output" ]; then
                printf '\n--- %s ---\n' "$output" >&2
                cat "$case_root/$output" >&2 || true
            fi
        done
    fi
    rm -rf "$fixture"
    exit "$result"
}
trap finish EXIT
contains() { grep -F -- "$2" "$1" > /dev/null || fail "missing '$2' in $1"; }
absent() { if [ -e "$1" ] || [ -L "$1" ]; then fail "unexpected path: $1"; fi; }
new_binary() { contains "$install_bin/$1" "# new $1"; }
old_binary() {
    printf 'old %s\n' "$1" > "$install_bin/$1"
    chmod +x "$install_bin/$1"
}
start_case() {
    case_name="$1"
    case_root="$fixture/$case_name"
    mkdir -p "$case_root/home/.local/bin" "$case_root/root/bin"
    install_bin="$case_root/root/bin"
    mode=normal
    printf 'victim must survive\n' > "$case_root/victim"
    export case_root install_bin mode
}
invoke() {
    status=0
    (
        cd "$repository"
        HOME="$case_root/home" PATH="$fixture/hooks:$PATH" CARGO_BUILD_JOBS=99 \
            bash tools/install.sh "$@"
    ) > "$case_root/stdout" 2> "$case_root/stderr" || status=$?
}
success() { [ "$status" -eq 0 ] || fail "unexpected exit $status"; }
failure() {
    [ "$status" -ne 0 ] || fail 'unexpected success'
    if grep -F 'Installed from this source tree' "$case_root/stdout" > /dev/null; then
        fail 'false success report'
    fi
}
retained() {
    contains "$case_root/stderr" 'Private staging retained'
    contains "$case_root/stderr" 'No staging or .new paths are automatically deleted'
    staging="$(cat "$case_root/staging.path")"
}

start_case default
install_bin="$case_root/home/.local/bin"
invoke
success
new_binary rampage
new_binary rampage-worker
absent "$install_bin/rampage-ui"
absent "$install_bin/rampage-plugin-worker"
[ "$(wc -l < "$case_root/cargo.log" | tr -d ' ')" -eq 2 ] || fail 'unexpected default packages'
retained
contains "$staging/.crates.toml" 'fixture metadata'

start_case ui
invoke "$case_root/root" --ui
success
new_binary rampage-ui
absent "$install_bin/rampage-plugin-worker"

start_case plugins
invoke --plugins "$case_root/root"
success
new_binary rampage-plugin-worker
absent "$install_bin/rampage-ui"
[ "$(wc -l < "$case_root/cargo.log" | tr -d ' ')" -eq 3 ] || fail 'unexpected plugin packages'
contains "$case_root/cargo.log" rampage-plugin-worker

start_case both
invoke "$case_root/root" --plugins --ui
success
new_binary rampage-ui
new_binary rampage-plugin-worker

start_case retained_optional
for name in rampage rampage-worker rampage-ui rampage-plugin-worker; do old_binary "$name"; done
invoke "$case_root/root"
success
for name in rampage rampage-worker rampage-ui rampage-plugin-worker; do new_binary "$name"; done

start_case nonexecutable_optional
printf 'old optional worker\n' > "$install_bin/rampage-plugin-worker"
invoke "$case_root/root"
success
new_binary rampage-plugin-worker

start_case root_with_spaces
install_bin="$case_root/root with spaces/bin"
invoke "$case_root/root with spaces" --plugins
success
new_binary rampage-plugin-worker

start_case unrelated_new
printf 'unrelated pending file\n' > "$install_bin/rampage.new"
ln -s "$case_root/victim" "$install_bin/rampage-worker.new"
ln -s missing "$install_bin/rampage-plugin-worker.new"
ln -s missing-ui "$install_bin/rampage-ui.new"
invoke "$case_root/root" --plugins --ui
success
contains "$install_bin/rampage.new" 'unrelated pending file'
[ -L "$install_bin/rampage-worker.new" ] || fail 'pending symlink removed'
[ -L "$install_bin/rampage-plugin-worker.new" ] || fail 'dangling pending symlink removed'
[ -L "$install_bin/rampage-ui.new" ] || fail 'UI pending symlink removed'
contains "$case_root/victim" 'victim must survive'

start_case unexpected_directory
mkdir "$install_bin/rampage"
printf 'unrelated\n' > "$install_bin/rampage/sentinel"
invoke "$case_root/root"
failure
contains "$install_bin/rampage/sentinel" unrelated
absent "$case_root/cargo.log"

start_case unexpected_symlink
ln -s "$case_root/victim" "$install_bin/rampage"
invoke "$case_root/root"
failure
[ -L "$install_bin/rampage" ] || fail 'destination symlink removed'
contains "$case_root/victim" 'victim must survive'

start_case build_failure
mode=build_failure
old_binary rampage
old_binary rampage-worker
invoke "$case_root/root"
failure
retained
contains "$install_bin/rampage" 'old rampage'
contains "$install_bin/rampage-worker" 'old rampage-worker'
absent "$case_root/moves.log"
contains "$case_root/stderr" 'Install incomplete'

start_case partial_publication
mode=move_failure
old_binary rampage
old_binary rampage-worker
invoke "$case_root/root"
failure
retained
new_binary rampage-worker
contains "$install_bin/rampage" 'old rampage'
contains "$case_root/stderr" 'Confirmed publication before failure: rampage-worker'
contains "$case_root/stderr" 'Publication may have changed rampage;'
contains "$staging/bin/rampage" '# new rampage'

start_case partial_move_failure
mode=move_failure_after
old_binary rampage
old_binary rampage-worker
invoke "$case_root/root"
failure
retained
new_binary rampage-worker
absent "$install_bin/rampage"
contains "$staging/previous/rampage" 'old rampage'
contains "$case_root/stderr" 'Publication may have changed rampage;'

start_case stage_swap
mode=stage_swap
invoke "$case_root/root"
failure
retained
contains "$staging/sentinel" 'unrelated stage occupant'
contains "$staging.moved/bin/rampage" '# new rampage'
absent "$install_bin/rampage"
absent "$install_bin/rampage-worker"

start_case stage_occupant
mode=stage_occupant
invoke "$case_root/root"
success
retained
contains "$staging/sentinel" 'unrelated stage occupant'

start_case staged_symlink
mode=staged_symlink
invoke "$case_root/root"
failure
retained
[ -L "$staging/bin" ] || fail 'unexpected staging symlink removed'
contains "$case_root/alternate-bin/sentinel" 'unrelated staged target'
contains "$case_root/original-staged-bin/rampage" '# new rampage'
absent "$install_bin/rampage-worker"

start_case destination_swap
mode=destination_swap
old_binary rampage
old_binary rampage-worker
invoke "$case_root/root"
failure
retained
contains "$install_bin/sentinel" 'unrelated destination occupant'
staging="$(cat "$case_root/staging.path")"
contains "$install_bin.moved/${staging##*/}/previous/rampage-worker" 'old rampage-worker'
contains "$install_bin.moved/rampage" 'old rampage'
contains "$case_root/stderr" 'Publication may have changed rampage-worker;'

start_case false_success
mode=false_success
old_binary rampage
old_binary rampage-worker
invoke "$case_root/root"
failure
contains "$case_root/stderr" 'Previous destination identity is uncertain'
contains "$install_bin/rampage-worker" 'old rampage-worker'

start_case link_false_success
mode=link_false_success
invoke "$case_root/root"
failure
contains "$case_root/stderr" 'Publication identity is uncertain'
absent "$install_bin/rampage-worker"

start_case existing_late_symlink
mode=existing_late_symlink
old_binary rampage-worker
invoke "$case_root/root"
failure
retained
[ -L "$staging/previous/rampage-worker" ] || fail 'unexpected replacement symlink discarded'
contains "$case_root/displaced-worker" 'old rampage-worker'
contains "$case_root/victim" 'victim must survive'

start_case backup_occupant
mode=backup_occupant
old_binary rampage-worker
invoke "$case_root/root"
failure
retained
contains "$staging/previous/rampage-worker" 'unrelated backup occupant'
contains "$install_bin/rampage-worker" 'old rampage-worker'
absent "$case_root/moves.log"

for occupant in backup_directory backup_live_symlink backup_dangling_symlink; do
    start_case "$occupant"
    mode="$occupant"
    old_binary rampage-worker
    invoke "$case_root/root"
    failure
    retained
    contains "$case_root/stderr" 'Unexpected backup occupant preserved'
    contains "$install_bin/rampage-worker" 'old rampage-worker'
    absent "$case_root/moves.log"
    if [ "$occupant" = backup_directory ]; then
        contains "$staging/previous/rampage-worker/sentinel" 'unrelated backup directory'
        absent "$staging/previous/rampage-worker/rampage-worker"
    else
        [ -L "$staging/previous/rampage-worker" ] || fail 'backup symlink removed'
        contains "$case_root/victim" 'victim must survive'
        absent "$case_root/missing-backup-target"
    fi
done

start_case previous_directory_symlink
mode=previous_directory_symlink
old_binary rampage-worker
invoke "$case_root/root"
failure
retained
[ -L "$staging/previous" ] || fail 'previous directory symlink removed'
contains "$install_bin/rampage-worker" 'old rampage-worker'
contains "$case_root/alternate-previous/sentinel" 'unrelated previous directory'
absent "$case_root/alternate-previous/rampage-worker"
absent "$case_root/moves.log"

start_case link_destination_swap
mode=link_destination_swap
invoke "$case_root/root"
failure
contains "$install_bin/sentinel" 'unrelated destination occupant'
contains "$install_bin.moved/rampage-worker" '# new rampage-worker'
absent "$install_bin.moved/rampage"
contains "$case_root/stderr" 'Publication may have changed rampage-worker;'

start_case link_stage_swap
mode=link_stage_swap
invoke "$case_root/root"
failure
retained
contains "$staging/sentinel" 'unrelated stage occupant'
contains "$staging.moved/bin/rampage" '# new rampage'
new_binary rampage-worker
absent "$install_bin/rampage"
contains "$case_root/stderr" 'Publication may have changed rampage-worker;'

start_case link_failure_after
mode=link_failure_after
invoke "$case_root/root"
failure
retained
new_binary rampage-worker
absent "$install_bin/rampage"
contains "$case_root/stderr" 'Publication may have changed rampage-worker;'
if grep -F 'Confirmed publication before failure:' "$case_root/stderr" > /dev/null; then
    fail 'failed link was falsely confirmed'
fi

start_case destination_symlink
mode=destination_symlink
invoke "$case_root/root"
failure
[ -L "$install_bin/rampage" ] || fail 'late destination symlink removed'
contains "$case_root/victim" 'victim must survive'

start_case late_occupant
mode=late_occupant
invoke "$case_root/root"
failure
[ -L "$install_bin/rampage-worker" ] || fail 'racing destination occupant removed'
contains "$case_root/victim" 'victim must survive'

start_case late_directory
mode=late_directory
invoke "$case_root/root"
failure
contains "$install_bin/rampage-worker/sentinel" 'unrelated directory'
absent "$install_bin/rampage-worker/rampage-worker"

start_case invalid_arguments
invoke "$case_root/root" --unknown
failure
[ "$status" -eq 2 ] || fail 'invalid argument status'
absent "$case_root/cargo.log"
contains "$case_root/stderr" '[--plugins]'

echo 'Installer fixture regressions passed (no real Cargo, installed programs or user roots used).'
