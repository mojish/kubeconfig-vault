#!/bin/sh
set -eu

if [ "$#" -ne 2 ] || ! printf '%s\n' "$1" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
    printf 'Usage: %s vMAJOR.MINOR.PATCH NEW_OUTPUT_DIRECTORY\n' "$0" >&2
    exit 2
fi

tag=$1
repo=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -- "$2"
out=$(CDPATH='' cd -- "$2" && pwd)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/kcv-release.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
trap 'exit 1' HUP INT TERM

cd "$repo/age-app"
go list -m >/dev/null
npm ci --include=dev --ignore-scripts --no-audit --no-fund
npm run build:web
go mod download
go mod verify

cp "$repo/LICENSE" "$scratch/LICENSE"
for os in linux darwin; do
    for arch in amd64 arm64; do
        printf 'Building %s/%s\n' "$os" "$arch"
        CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
            -ldflags "-X main.version=$tag" -o "$scratch/kube-unlock-age" .
        tar -czf "$out/kubeconfig-vault-$os-$arch.tar.gz" -C "$scratch" kube-unlock-age LICENSE
    done
done

cp "$repo/install.sh" "$out/install.sh"
cd "$out"
sha256sum install.sh kubeconfig-vault-*.tar.gz > SHA256SUMS
printf 'Release assets prepared in %s\n' "$out"
