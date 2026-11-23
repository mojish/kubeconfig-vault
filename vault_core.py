"""Encrypted generations and token-only kubeconfig projection. No implicit inputs."""

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import yaml

from probe import decode, encode

VERSION = 1
AAD = b"kube-unlock source v1"
MAX_CONFIG = 4 * 1024 * 1024


class VaultError(ValueError):
    pass


class UniqueLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in result:
            raise VaultError("Configuration contains a duplicate or non-string mapping key.")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def parse(text):
    if not isinstance(text, str) or len(text.encode()) > MAX_CONFIG:
        raise VaultError("Configuration exceeds the size limit.")
    try:
        config = yaml.load(text, Loader=UniqueLoader)
    except yaml.YAMLError:
        # YAML exceptions contain source snippets, potentially including tokens.
        raise VaultError("Invalid kubeconfig YAML. The previous generation is unchanged.") from None
    if not isinstance(config, dict) or config.get("apiVersion") != "v1" or config.get("kind") != "Config":
        raise VaultError("Expected a Kubernetes v1 Config.")
    return config


def named(config, field, singular):
    result = {}
    rows = config.get(field, [])
    if not isinstance(rows, list):
        raise VaultError(f"Expected a list in {field}.")
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str) or not row["name"]:
            raise VaultError(f"Invalid named entry in {field}.")
        if row["name"] in result or not isinstance(row.get(singular), dict):
            raise VaultError(f"Duplicate or invalid entry in {field}.")
        result[row["name"]] = row[singular]
    return result


def canonical_cluster(cluster, base):
    allowed = {"server", "certificate-authority", "certificate-authority-data", "insecure-skip-tls-verify", "tls-server-name", "proxy-url", "disable-compression"}
    if set(cluster) - allowed:
        raise VaultError("Unsupported cluster fields. No fields were silently discarded.")
    out = copy.deepcopy(cluster)
    server = urlsplit(out.get("server", ""))
    if server.scheme != "https" or not server.hostname or server.username or server.password or server.fragment or server.query:
        raise VaultError("Cluster servers must be HTTPS URLs without embedded credentials, query, or fragment.")
    if out.get("proxy-url"):
        proxy = urlsplit(out["proxy-url"])
        if proxy.username or proxy.password:
            raise VaultError("Proxy URLs with embedded credentials are not supported.")
    if "certificate-authority" in out:
        if "certificate-authority-data" in out:
            raise VaultError("Specify one certificate authority source.")
        path = Path(out.pop("certificate-authority"))
        path = path if path.is_absolute() else Path(base) / path
        data = path.read_bytes()
        if len(data) > MAX_CONFIG:
            raise VaultError("Certificate authority file is too large.")
        out["certificate-authority-data"] = base64.b64encode(data).decode()
    return out


def cluster_binding(cluster):
    # ExecCredential cluster data normalizes absent false/empty values.
    keys = ["server", "certificate-authority-data", "insecure-skip-tls-verify", "tls-server-name", "proxy-url", "disable-compression"]
    value = {k: cluster[k] for k in keys if cluster.get(k)}
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def managed_projection(config):
    config = copy.deepcopy(config)
    config.pop("current-context", None)
    for row in config.get("contexts", []):
        row.get("context", {}).pop("namespace", None)
    # kubectl may write an empty preferences map.
    if not config.get("preferences"):
        config.pop("preferences", None)
    return config


def prepare(text, base, state, previous=None, token_files=False):
    config = parse(text)
    clusters = named(config, "clusters", "cluster")
    users = named(config, "users", "user")
    contexts = named(config, "contexts", "context")
    if not clusters or not users or not contexts:
        raise VaultError("At least one cluster, token user, and context are required.")
    normalized = {name: canonical_cluster(cluster, base) for name, cluster in clusters.items()}
    records = {}
    for name, auth in users.items():
        old = (previous or {}).get("records", {}).get(name, {})
        if set(auth) == {"token"} and isinstance(auth["token"], str) and auth["token"]:
            token = auth["token"]
        elif set(auth) == {"tokenFile"} and token_files:
            if old.get("token_file") == auth["tokenFile"]:
                token = old["token"]
            else:
                path = Path(auth["tokenFile"])
                path = path if path.is_absolute() else Path(base) / path
                with path.open() as stream:
                    token = stream.read(65537).strip()
            if not token:
                raise VaultError("An explicitly selected token file is empty.")
        else:
            raise VaultError("Only inline token users are supported by default. Token files require --allow-token-files. Exec, auth-provider, and private-key users are never executed or imported.")
        if any(c in token for c in "\r\n") or len(token) > 65536:
            raise VaultError("Invalid bearer token format.")
        records[name] = {"id": old.get("id", secrets.token_hex(16)), "token": token, "clusters": []}
        if "tokenFile" in auth:
            records[name]["token_file"] = auth["tokenFile"]
    for context in contexts.values():
        if context.get("cluster") not in clusters or context.get("user") not in users:
            raise VaultError("A context references a missing cluster or user.")
        if set(context) - {"cluster", "user", "namespace"}:
            raise VaultError("Unsupported context fields.")
        binding = cluster_binding(normalized[context["cluster"]])
        records[context["user"]]["clusters"].append(binding)
    if config.get("current-context") and config["current-context"] not in contexts:
        raise VaultError("The current context does not exist.")
    cli = str(Path(__file__).resolve().parent / "kube_unlock.py")
    generated = {
        "apiVersion": "v1", "kind": "Config",
        "clusters": [{"name": name, "cluster": data} for name, data in normalized.items()],
        "contexts": [{"name": name, "context": copy.deepcopy(data)} for name, data in contexts.items()],
        "current-context": config.get("current-context", ""),
        "users": [{"name": name, "user": {"exec": {
            "apiVersion": "client.authentication.k8s.io/v1", "command": "/usr/bin/python3",
            "args": [cli, "--state-dir", str(state), "credential", record["id"]],
            "interactiveMode": "Never", "provideClusterInfo": True,
        }}} for name, record in records.items()],
    }
    return {"text": text, "base": str(base), "records": records, "generated": generated, "token_files": token_files}


def private_directory(path):
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise VaultError("State directories must be owned by your user with mode 0700 and must not be symlinks.")
    return path


def write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class Store:
    def __init__(self, directory):
        self.path = private_directory(Path(directory).absolute())
        self.generations = private_directory(self.path / "generations")

    def current(self):
        pointer = self.path / "current"
        if not pointer.is_symlink():
            if pointer.exists():
                raise VaultError("Unexpected current-generation path.")
            return None
        target = os.readlink(pointer)
        parts = Path(target).parts
        if len(parts) != 2 or parts[0] != "generations" or len(parts[1]) != 32 or any(c not in "0123456789abcdef" for c in parts[1]):
            raise VaultError("Invalid generation pointer.")
        directory = private_directory(self.path / target)
        document = json.loads((directory / "vault.json").read_text())
        if document.get("version") != VERSION:
            raise VaultError("Unsupported vault version.")
        return parts[1], document

    def decrypt(self, document, key):
        try:
            payload = AESGCM(key).decrypt(decode(document["iv"]), decode(document["ciphertext"], MAX_CONFIG * 8), AAD)
            return json.loads(payload)
        except Exception:
            raise VaultError("Unable to decrypt the vault. No files were changed.") from None

    def commit(self, payload, key, recipients, expected=None):
        current = self.current()
        if (current[0] if current else None) != expected:
            raise VaultError("Vault changed concurrently. The editable copy has been preserved.")
        generation = secrets.token_hex(16)
        directory = private_directory(self.generations / generation)
        iv = secrets.token_bytes(12)
        ciphertext = AESGCM(key).encrypt(iv, json.dumps(payload).encode(), AAD)
        document = {"version": VERSION, "recipients": recipients, "iv": encode(iv), "ciphertext": encode(ciphertext)}
        write_private(directory / "vault.json", json.dumps(document).encode())
        write_private(directory / "kubeconfig", yaml.safe_dump(payload["generated"], sort_keys=False).encode())
        sync_directory(directory)
        sync_directory(self.generations)
        temporary = self.path / (".current-" + generation)
        temporary.symlink_to(Path("generations") / generation)
        os.replace(temporary, self.path / "current")
        sync_directory(self.path)
        # Keep the current generation and the three most recent older generations.
        older = sorted(
            [p for p in self.generations.iterdir() if p.name != generation and len(p.name) == 32 and all(c in "0123456789abcdef" for c in p.name) and p.is_dir() and not p.is_symlink()],
            key=lambda p: p.stat().st_mtime, reverse=True,
        )
        for path in older[3:]:
            try:
                shutil.rmtree(path)
            except OSError:
                # A cleanup failure must not report the already committed save as failed.
                pass
        return generation
