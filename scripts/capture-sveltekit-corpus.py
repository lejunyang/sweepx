#!/usr/bin/env python3
"""Run pinned SvelteKit sync in disposable projects and record its unmodified output.

This developer-only acquisition tool needs network access. It never runs from a user project or
loads their environment/configuration. Normal Rust tests consume the checked-in recordings offline.
The recorded signatures establish generated format only, never exclusive ownership or inactivity.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import signal
import stat
import subprocess
import tempfile
import time


CASES = (
    ("1.0.0", {"@sveltejs/kit": "1.0.0", "svelte": "3.55.0", "vite": "4.0.4"}),
    ("2.0.0", {"@sveltejs/kit": "2.0.0", "svelte": "4.2.8", "vite": "5.0.10",
               "@sveltejs/vite-plugin-svelte": "3.0.0"}),
)
MAX_OUTPUT = 1024 * 1024
MAX_FILE = 256 * 1024


def run(command, cwd, env, timeout=180, max_output=MAX_OUTPUT):
    """Bound output/deadline, stop the task-owned group and reap its direct child on every exit."""
    if os.name != "posix":
        raise ValueError("corpus acquisition currently requires POSIX process groups")
    process = subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, start_new_session=True)
    output = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + timeout
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError("tool deadline exceeded")
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    elif len(output) + len(chunk) > max_output:
                        raise ValueError("tool output budget exceeded")
                    else:
                        output.extend(chunk)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("tool deadline exceeded")
            try:
                code = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired as error:
                raise ValueError("tool deadline exceeded") from error
        if code != 0:
            raise ValueError(f"tool exited {code}: {output.decode(errors='replace')[-4096:]}")
        return bytes(output)
    finally:
        # Descendants can outlive a successfully exited leader. This process group belongs only
        # to this invocation; never search for or stop unrelated processes by executable name.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        process.stdout.close()


def digest(content):
    return hashlib.sha256(content).hexdigest()


def read_file(path):
    """Read a bounded ordinary file without following a final link or waiting on a FIFO."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE:
            raise ValueError(f"invalid or oversized recording: {path.name}")
        data = source.read(MAX_FILE + 1)
        after = os.fstat(source.fileno())
        if (len(data) > MAX_FILE or len(data) != before.st_size
                or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError(f"recording changed or exceeded its bound: {path.name}")
        return data


def capture(node, pnpm, output, from_recordings=None):
    node = node.resolve(strict=True)
    pnpm = pnpm.resolve(strict=True)
    # mkdir without exist_ok guarantees that even a prior partial capture is never overwritten.
    output.mkdir(parents=False)
    with tempfile.TemporaryDirectory(prefix="sweepx-sveltekit-corpus-") as temporary:
        scratch = Path(temporary).resolve()
        home = scratch / "home"
        home.mkdir()
        env = {"PATH": str(node.parent) + ":/usr/bin:/bin", "HOME": str(home),
               "TMPDIR": str(scratch), "LANG": "C", "LC_ALL": "C", "CI": "true",
               "NO_COLOR": "1"}
        runtime = run([str(node), "--version"], scratch, env).decode().strip()
        manager = run([str(node), str(pnpm), "--version"], scratch, env).decode().strip()
        for version, dependencies in CASES:
            project = scratch / version
            project.mkdir()
            inputs = {
                "package.json": json.dumps({"name": "sweepx-corpus", "private": True,
                                            "type": "module", "devDependencies": dependencies},
                                           indent=2) + "\n",
                "svelte.config.js": "export default {};\n",
                "src/routes/+page.svelte": "<p>SweepX generated-format fixture</p>\n",
                "tsconfig.json": '{"extends":"./.svelte-kit/tsconfig.json"}\n',
            }
            for name, content in inputs.items():
                path = project / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8", newline="\n")
            install = [str(node), str(pnpm), "install", "--ignore-scripts",
                       "--config.auto-install-peers=false", "--store-dir", str(scratch / "store"),
                       "--registry=https://registry.npmjs.org", "--reporter=append-only"]
            if from_recordings is not None:
                lock = from_recordings / f"sveltekit-{version}" / "pnpm-lock.yaml"
                (project / "pnpm-lock.yaml").write_bytes(read_file(lock))
                install.append("--frozen-lockfile")
            run(install, project, env)
            package = json.loads(read_file(project / "node_modules/@sveltejs/kit/package.json"))
            if package["version"] != version:
                raise ValueError("installed kit version differs from pinned input")
            # No prepare/postinstall scripts are admitted. Execute only the selected kit's actual
            # CLI and our controlled empty config, with no inherited private environment values.
            run([str(node), "node_modules/@sveltejs/kit/svelte-kit.js", "sync"], project, env)
            names = list(inputs) + ["pnpm-lock.yaml", ".svelte-kit/tsconfig.json",
                                   ".svelte-kit/ambient.d.ts", "node_modules/@sveltejs/kit/LICENSE"]
            case = output / f"sveltekit-{version}"
            case.mkdir()
            files = {}
            for name in names:
                path = project / name
                if not path.resolve(strict=True).is_relative_to(project):
                    raise ValueError(f"recording escapes the generated project: {name}")
                data = read_file(path)
                destination = case / name.removeprefix(".svelte-kit/")
                # Source tsconfig and generated tsconfig deliberately use separate names.
                if name == ".svelte-kit/tsconfig.json":
                    destination = case / "generated-tsconfig.json"
                elif name == "node_modules/@sveltejs/kit/LICENSE":
                    destination = case / "UPSTREAM-LICENSE"
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
                files[destination.relative_to(case).as_posix()] = {"bytes": len(data),
                                                                  "sha256": digest(data)}
            receipt = {"schema": "sweepx.generated-format-recording/v1", "tool": "@sveltejs/kit",
                       "version": version, "recordedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
                       "host": {"os": platform.system(), "arch": platform.machine()},
                       "node": runtime, "pnpm": manager, "requestedEnvironmentKeys": sorted(env),
                       "installScripts": False, "generator": "node @sveltejs/kit/svelte-kit.js sync",
                       "scope": "default empty config; generated signatures only; report-only",
                       "files": files}
            (case / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
            print(f"recorded @sveltejs/kit {version}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", required=True, type=Path)
    parser.add_argument("--pnpm", required=True, type=Path, help="pnpm CLI JavaScript entry point")
    parser.add_argument("--output", required=True, type=Path, help="new directory under an existing parent")
    parser.add_argument("--from-recordings", type=Path, help="reuse recorded dependency locks with frozen install")
    args = parser.parse_args()
    capture(args.node, args.pnpm, args.output, args.from_recordings)


if __name__ == "__main__":
    main()
