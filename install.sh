#!/bin/sh
set -eu

# The release packager fills this in before generating SHA256SUMS.
release_tag=''

usage() {
    printf 'Usage: %s [--source | --from-dir RELEASE_DIR] [BIN_DIRECTORY]\n' "$0"
    printf 'Install the latest published binary in ~/.local/bin by default.\n'
    printf 'Use --source to build from a checkout or --from-dir to install downloaded assets.\n'
}

log() {
    printf '[kubeconfig-vault] %s\n' "$1" >&2
}

fail() {
    printf '[kubeconfig-vault] Error: %s\n' "$1" >&2
    exit 1
}

require() {
    command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

fetch() {
    curl -q -fsS --proto '=https' --proto-redir '=https' \
        --connect-timeout 15 --max-time 90 --retry 2 --retry-max-time 120 "$@"
}

mode=download
release_dir=
case "${1:-}" in
    -h|--help) usage; exit 0 ;;
    --source) mode=source; shift ;;
    --from-dir)
        if [ "$#" -lt 2 ] || [ ! -d "$2" ]; then
            fail 'Choose an existing directory containing the release archive and SHA256SUMS.'
        fi
        mode=offline
        release_dir=$(CDPATH='' cd -- "$2" && pwd)
        shift 2 ;;
esac
directory_arg=${1:-}
if [ "$#" -gt 1 ] || [ "${directory_arg#-}" != "$directory_arg" ]; then
    usage >&2
    exit 2
fi

case "$(uname -s)" in
    Linux) os=linux ;;
    Darwin) os=darwin ;;
    *) fail 'Kubeconfig Vault supports Linux and macOS.' ;;
esac
case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) fail 'Choose a machine with a 64-bit Intel/AMD or ARM processor.' ;;
esac

bin_dir=${1:-"$HOME/.local/bin"}
case "$bin_dir" in
    /*) ;;
    *) bin_dir="$PWD/$bin_dir" ;;
esac

target="$bin_dir/kubeconfig-vault"
legacy="$bin_dir/kube-unlock-age"
next_command=setup
if [ -f "$target" ] || [ -f "$legacy" ]; then next_command=status; fi
if [ -L "$target" ] || { [ -e "$target" ] && [ ! -f "$target" ]; }; then
    fail "Choose an install directory with a regular file or unused path at $target"
fi
if [ -L "$legacy" ]; then
    [ "$(readlink "$legacy")" = kubeconfig-vault ] || fail "A different symlink already exists at $legacy"
elif [ -e "$legacy" ] && [ ! -f "$legacy" ]; then
    fail "Choose an install directory with a regular file or unused path at $legacy"
fi

if [ "$mode" = source ]; then
    repo=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
    cd "$repo/age-app" || fail 'Source builds require the full repository checkout.'
    require go
    minimum=$(awk '$1 == "go" { print $2; exit }' go.mod)
    if ! go list -m >/dev/null; then
        fail "Source builds need Go $minimum or newer. Use the published binary to install without Go."
    fi
    require node
    require npm
    node -e 'const [major, minor] = process.versions.node.split(".").map(Number); process.exit(major > 22 || major === 22 && minor >= 12 ? 0 : 1)' || fail 'Source builds need Node.js 22.12 or newer.'
fi

# Keep the previous binary in place until the replacement is ready.
mkdir -p "$bin_dir"
stage=$(mktemp -d "$bin_dir/.kubeconfig-vault.XXXXXX")
trap 'rm -rf "$stage"' EXIT
trap 'exit 1' HUP INT TERM

if [ "$mode" = source ]; then
    log "Building from source for $os/$arch"
    log "Installing browser dependencies"
    npm ci --include=dev --ignore-scripts --no-audit --no-fund >&2
    log "Building browser assets"
    npm run build:web >&2
    log "Compiling the CLI"
    go build -trimpath -o "$stage/kubeconfig-vault" .
else
    asset="kubeconfig-vault-$os-$arch.tar.gz"
    if [ "$mode" = download ]; then
        require curl
        releases='https://github.com/mojish/kubeconfig-vault/releases'
        if [ -z "$release_tag" ]; then
            # A source checkout has no stamped tag. Resolve latest just once.
            log "Looking up the latest GitHub release"
            redirect=$(fetch \
                -o /dev/null -w '%{redirect_url}' "$releases/latest") ||
                fail 'Unable to look up the latest GitHub release.'
            case "$redirect" in
                "$releases/tag/"*) release_tag=${redirect#"$releases/tag/"} ;;
                *) fail 'GitHub did not return a release tag.' ;;
            esac
        fi
        case "$release_tag" in *[!v0-9.]*) fail 'Invalid GitHub release tag.' ;; esac
        printf '%s\n' "$release_tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' ||
            fail 'Invalid GitHub release tag.'
        base="$releases/download/$release_tag"
        log "Installing $release_tag for $os/$arch"
        for name in SHA256SUMS "$asset"; do
            log "Downloading $name"
            fetch -L -o "$stage/$name" "$base/$name" ||
                fail "Could not download $name from $base. Check the release and your connection, then retry."
        done
        release_dir=$stage
    else
        log "Installing from local release files for $os/$arch"
    fi
    if [ ! -f "$release_dir/$asset" ] || [ ! -f "$release_dir/SHA256SUMS" ]; then
        fail "Keep $asset and SHA256SUMS in the same directory."
    fi
    if [ "$mode" = offline ]; then
        cp "$release_dir/$asset" "$stage/$asset" || fail "Could not stage $asset."
        cp "$release_dir/SHA256SUMS" "$stage/SHA256SUMS" || fail "Could not stage the checksum manifest."
        release_dir=$stage
    fi
    log "Checking SHA-256 for $asset"
    expected=$(awk -v name="$asset" '$2 == name { count++; hash=$1; if (NF != 2) exit 1 }
        END { if (count != 1 || length(hash) != 64 || hash ~ /[^0-9a-fA-F]/) exit 1; print tolower(hash) }' \
        "$release_dir/SHA256SUMS") || fail "Expected one valid checksum for $asset in SHA256SUMS."
    if [ "$os" = darwin ]; then
        require shasum
        actual=$(shasum -a 256 < "$release_dir/$asset")
    else
        require sha256sum
        actual=$(sha256sum < "$release_dir/$asset")
    fi
    if [ "${#expected}" -ne 64 ] || [ "$expected" != "${actual%% *}" ]; then
        fail 'Release checksum mismatch. The installed binary was left in place.'
    fi
    # Older published installers also extract this exact member from releases/latest.
    log "Extracting the verified executable"
    tar -xOf "$release_dir/$asset" kube-unlock-age > "$stage/kubeconfig-vault" ||
        fail "Could not extract the executable from $asset."
    [ -s "$stage/kubeconfig-vault" ] || fail 'The release archive does not contain the executable.'
    chmod 755 "$stage/kubeconfig-vault"
fi

log "Installing the executable in $bin_dir"
ln -s kubeconfig-vault "$stage/kube-unlock-age"
mv -f "$stage/kubeconfig-vault" "$target"
mv -f "$stage/kube-unlock-age" "$legacy"
printf 'Installed %s\n' "$target"
if [ "$next_command" = status ]; then
    log "If a previous helper is running, run kubeconfig-vault stop so the next session uses this executable."
fi
case ":${PATH:-}:" in
    *":$bin_dir:"*) log "Next, run kubeconfig-vault $next_command" ;;
    *) log "To use kubeconfig-vault by name, add $bin_dir to PATH, then run kubeconfig-vault $next_command." ;;
esac
