#!/bin/sh
set -eu

# Exercise the actual download installer against disposable curl responses.
repo=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
installer=${1:-"$repo/install.sh"}
tag=${2:-v1.2.3}
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
mkdir "$scratch/mock" "$scratch/bin"
export KCV_FIXTURE="$scratch" KCV_FIXTURE_TAG="$tag"
printf 'fixture binary\n' > "$scratch/kube-unlock-age"
case "$(uname -s)" in Darwin) os=darwin ;; Linux) os=linux ;; esac
case "$(uname -m)" in arm64|aarch64) arch=arm64 ;; x86_64|amd64) arch=amd64 ;; esac
asset="kubeconfig-vault-$os-$arch.tar.gz"
tar -czf "$scratch/$asset" -C "$scratch" kube-unlock-age
(cd "$scratch" && shasum -a 256 "$asset" > SHA256SUMS)
cat > "$scratch/mock/curl" <<'CURL'
#!/bin/sh
set -eu
base=https://github.com/mojish/kubeconfig-vault/releases
while [ "$#" -gt 1 ]; do
    case "$1" in -o) out=$2; shift 2 ;; *) shift ;; esac
done
printf '%s\n' "$1" >> "$KCV_FIXTURE/calls"
case "$1" in
    "$base/latest")
        latest=$KCV_FIXTURE_TAG
        if [ -f "$KCV_FIXTURE/advanced" ]; then latest=v99.99.99; fi
        printf '%s/tag/%s' "$base" "$latest" ;;
    "$base/download/$KCV_FIXTURE_TAG/"*)
        cp "$KCV_FIXTURE/${1##*/}" "$out"
        if [ "${1##*/}" = SHA256SUMS ]; then touch "$KCV_FIXTURE/advanced"; fi ;;
    *) exit 22 ;;
esac
CURL
chmod +x "$scratch/mock/curl"
export PATH="$scratch/mock:$PATH"
base=https://github.com/mojish/kubeconfig-vault/releases
{
    if [ "$#" -eq 0 ]; then printf '%s/latest\n' "$base"; fi
    printf '%s/download/%s/%s\n' "$base" "$tag" SHA256SUMS "$base" "$tag" "$asset"
} > "$scratch/expected"
sh "$installer" "$scratch/bin"
diff "$scratch/expected" "$scratch/calls"
cmp "$scratch/kube-unlock-age" "$scratch/bin/kubeconfig-vault"
test "$(readlink "$scratch/bin/kube-unlock-age")" = kubeconfig-vault

# Once the manifest has been selected, latest can point elsewhere. The mock
# serves only immutable asset URLs; a mismatched archive must preserve the binary.
printf 'damaged\n' >> "$scratch/$asset"
rm "$scratch/advanced"
if sh "$installer" "$scratch/bin" > "$scratch/result" 2>&1; then exit 1; fi
grep -q 'checksum mismatch' "$scratch/result"
cmp "$scratch/kube-unlock-age" "$scratch/bin/kubeconfig-vault"
printf 'PASS: version-pinned downloads and failed-upgrade preservation\n'
