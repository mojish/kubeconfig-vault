#!/bin/sh
set -eu

usage() {
    printf 'Usage: %s [--source | --from-dir RELEASE_DIR] [BIN_DIRECTORY]\n' "$0"
    printf 'Install the latest published binary in ~/.local/bin by default.\n'
    printf 'Use --source to build from a checkout or --from-dir to install downloaded assets.\n'
}

fail() {
    printf '%s\n' "$1" >&2
    exit 1
}

require() {
    command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
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
    npm ci --include=dev --ignore-scripts --no-audit --no-fund
    npm run build:web
    go build -trimpath -o "$stage/kubeconfig-vault" .
else
    asset="kubeconfig-vault-$os-$arch.tar.gz"
    if [ "$mode" = download ]; then
        require curl
        base='https://github.com/mojish/kubeconfig-vault/releases/latest/download'
        for name in SHA256SUMS "$asset"; do
            code=0
            curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 15 \
                -o "$stage/$name" "$base/$name" || code=$?
            if [ "$code" -eq 22 ]; then
                fail 'No published release asset is available. Check GitHub Releases or run ./install.sh --source from a checkout.'
            elif [ "$code" -ne 0 ]; then
                fail "Unable to download $name. Check your connection and try again."
            fi
        done
        release_dir=$stage
    fi
    if [ ! -f "$release_dir/$asset" ] || [ ! -f "$release_dir/SHA256SUMS" ]; then
        fail "Keep $asset and SHA256SUMS in the same directory."
    fi
    expected=$(awk -v name="$asset" '$2 == name { print $1 }' "$release_dir/SHA256SUMS")
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
    tar -xOf "$release_dir/$asset" kube-unlock-age > "$stage/kubeconfig-vault"
    [ -s "$stage/kubeconfig-vault" ] || fail 'The release archive does not contain the executable.'
    chmod 755 "$stage/kubeconfig-vault"
fi

ln -s kubeconfig-vault "$stage/kube-unlock-age"
mv -f "$stage/kubeconfig-vault" "$target"
mv -f "$stage/kube-unlock-age" "$legacy"
printf 'Installed %s\n' "$target"
