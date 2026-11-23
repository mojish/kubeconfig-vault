#!/usr/bin/env python3
"""Local credential helper. Import requires an explicit, user-selected file."""

import argparse
import json
import os
from pathlib import Path
import resource
import shlex
import socket
import subprocess
import sys
import time

from runtime import MAX_IPC, serve
from vault_core import MAX_CONFIG, VaultError, private_directory, write_private


def connect(state, ttl):
    state = private_directory(state)
    address = str(state / "session.sock")
    if len(address.encode()) >= 104:
        raise VaultError("State path is too long for a Unix socket. Choose a shorter --state-dir.")
    launched = False
    for _ in range(50):
        client = socket.socket(socket.AF_UNIX)
        client.settimeout(310)
        try:
            client.connect(address)
            return client
        except (FileNotFoundError, ConnectionRefusedError):
            client.close()
            if not launched:
                subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--state-dir", str(state),
                                  "--session-seconds", str(ttl), "daemon"], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
                launched = True
            time.sleep(0.1)
    raise VaultError("The local session process did not start. Run the daemon command to diagnose it.")


def rpc(state, ttl, operation, **values):
    with connect(state, ttl) as client:
        client.sendall(json.dumps({"operation": operation, **values}).encode() + b"\n")
        response = client.makefile("rb").readline(MAX_IPC + 1)
    if len(response) > MAX_IPC:
        raise VaultError("Response exceeds the size limit.")
    data = json.loads(response)
    if "error" in data:
        raise VaultError(data["error"])
    return data["result"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=Path.home() / ".local/share/kube-unlock")
    parser.add_argument("--session-seconds", type=int, default=3600)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ["status", "lock", "unlock", "stop", "backups", "daemon", "probe", "edit"]:
        commands.add_parser(name)
    importing = commands.add_parser("import")
    importing.add_argument("source", type=Path)
    importing.add_argument("--allow-token-files", action="store_true")
    config = commands.add_parser("config").add_subparsers(dest="action", required=True)
    for name in ["unlock", "discard", "repair"]:
        config.add_parser(name)
    config.add_parser("lock").add_argument("--accept-connection-changes", action="store_true")
    commands.add_parser("key").add_subparsers(dest="action", required=True).add_parser("add")
    commands.add_parser("export").add_argument("output", type=Path)
    commands.add_parser("restore").add_argument("generation")
    commands.add_parser("credential").add_argument("identity")
    args = parser.parse_args()
    if not 30 <= args.session_seconds <= 86400:
        parser.error("--session-seconds must be between 30 and 86400")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    state = args.state_dir.absolute()
    if args.command == "daemon":
        serve(state, args.session_seconds)
        return
    if args.command == "probe":
        subprocess.run([sys.executable, str(Path(__file__).with_name("probe.py"))], check=True)
        return
    call = lambda op, **values: rpc(state, args.session_seconds, op, **values)
    if args.command == "import":
        source = args.source.absolute()
        if source.stat().st_size > MAX_CONFIG:
            raise VaultError("Selected kubeconfig exceeds the size limit.")
        with source.open() as stream:
            text = stream.read(MAX_CONFIG + 1)
        result = call("import", text=text, base=str(source.parent), token_files=args.allow_token_files)
        print("Encrypted vault created. Original file was left unchanged.")
        print("Connection kubeconfig:", result["config"])
        print("Add a backup security key with key add before relying on this vault as the only copy.")
        print("Existing plaintext copies still allow access. Review them after verifying the candidate configuration.")
    elif args.command == "credential":
        info = json.loads(os.environ.get("KUBERNETES_EXEC_INFO", "{}"))
        if info.get("apiVersion") != "client.authentication.k8s.io/v1" or info.get("kind") != "ExecCredential":
            raise VaultError("This subcommand must be invoked through the Kubernetes exec protocol.")
        print(json.dumps(call("credential", identity=args.identity, cluster=info.get("spec", {}).get("cluster"))))
    elif args.command == "config":
        result = call("config-" + args.action, accept_connections=getattr(args, "accept_connection_changes", False))
        print(result["path"] if "path" in result else json.dumps(result))
    elif args.command == "edit":
        path = call("config-unlock")["path"]
        editor = shlex.split(os.environ.get("VISUAL") or os.environ.get("EDITOR") or "vi")
        if subprocess.run([*editor, path]).returncode:
            raise VaultError("Editor exited with an error. The editable copy was preserved.")
        print(json.dumps(call("config-lock")))
    elif args.command == "key":
        print(json.dumps(call("key-add")))
    elif args.command == "export":
        result = call("export")
        write_private(args.output, result["text"].encode())
        print("Wrote plaintext export to the explicitly selected path. Protect or remove it after use.")
    elif args.command == "restore":
        print(json.dumps(call("restore", generation=args.generation)))
    else:
        print(json.dumps(call(args.command)))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted. Unsaved edit files, if any, were preserved.", file=sys.stderr)
        sys.exit(130)
    except (VaultError, OSError, ValueError):
        # Show safe application errors, but never raw parser or filesystem data.
        exc = sys.exc_info()[1]
        print(str(exc) if isinstance(exc, VaultError) else "Local operation failed. Check the selected path and session process.", file=sys.stderr)
        sys.exit(1)
