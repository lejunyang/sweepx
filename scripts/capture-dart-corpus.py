#!/usr/bin/env python3
"""Record offline pub output from explicit Dart 2.18.0/3.6.0 SDKs in controlled projects.

No SDK download or global setup occurs here. Only disposable project/home/cache paths are used;
production scans never execute this tool. Raw output is format evidence, not ownership authority.
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
from pathlib import Path
import platform
import re
import tempfile


# Share existing acquisition bounds/process cleanup instead of maintaining a second runner.
SPEC = importlib.util.spec_from_file_location(
    "sdk_corpus_io", Path(__file__).with_name("capture-sveltekit-corpus.py")
)
io = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(io)


def inputs(members):
    declaration = "name: sweepx_corpus\npublish_to: none\nenvironment:\n  sdk: '>=2.18.0 <4.0.0'\n"
    files = {"pubspec.yaml": declaration, "lib/example.dart": "void main() {}\n"}
    if members:
        files["pubspec.yaml"] = ("name: sweepx_corpus\npublish_to: none\nenvironment:\n"
                                "  sdk: ^3.6.0\nworkspace:\n" +
                                "".join(f"  - '{member}'\n" for member in members))
        for index, member in enumerate(members):
            files[f"{member}/pubspec.yaml"] = (f"name: member_{index}\npublish_to: none\n"
                                              "environment:\n  sdk: ^3.6.0\nresolution: workspace\n")
            files[f"{member}/lib/example.dart"] = "void main() {}\n"
        # Pub should remove only the obsolete member map, leaving nearby personal files intact.
        files[f"{members[0]}/.dart_tool/personal-notes"] = "keep these user notes\n"
    return files


def capture(dart2, dart3, output):
    sdks = {"2.18.0": dart2.resolve(strict=True), "3.6.0": dart3.resolve(strict=True)}
    output.mkdir(parents=False)
    with tempfile.TemporaryDirectory(prefix="sweepx-dart-corpus-") as temporary:
        scratch = Path(temporary).resolve()
        home = scratch / "home"
        home.mkdir()
        env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(scratch),
               "LANG": "C", "LC_ALL": "C", "CI": "true", "DART_SUPPRESS_ANALYTICS": "true",
               "PUB_CACHE": str(scratch / "pub-cache")}
        versions = {}
        for version, dart in sdks.items():
            observed = io.run([str(dart), "--version"], scratch, env).decode().strip()
            match = re.search(r"Dart SDK version: (\S+)", observed)
            if match is None or match.group(1) != version:
                raise ValueError("SDK does not match the requested fixed version")
            io.run([str(dart), "--disable-analytics"], scratch, env)
            versions[version] = observed
        cases = [("dart-2.18.0-standalone", "2.18.0", []),
                 ("dart-3.6.0-standalone", "3.6.0", []),
                 ("dart-3.6.0-workspace", "3.6.0", ["packages/a", "packages/b"]),
                 ("dart-3.6.0-unicode-workspace", "3.6.0", ["packages/组件 a", "packages/b"])]
        for case_id, version, members in cases:
            project = scratch / case_id
            project.mkdir()
            source_inputs = inputs(members)
            for name, text in source_inputs.items():
                path = project / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8", newline="\n")
            removed = []
            if members:
                old = project / members[0] / ".dart_tool/package_config.json"
                old.write_text("{}\n", encoding="utf-8")
                removed.append(old.relative_to(project).as_posix())
            # Exercise workspace discovery from a member, not only the workspace root.
            cwd = project / members[0] if members else project
            io.run([str(sdks[version]), "pub", "get", "--offline"], cwd, env)
            if any((project / name).exists() for name in removed):
                raise ValueError("pub retained the obsolete member map")
            for name, text in source_inputs.items():
                if io.read_file(project / name) != text.encode():
                    raise ValueError(f"pub changed a controlled source/personal input: {name}")
            case = output / case_id
            case.mkdir()
            files = {}
            names = {name: name for name in source_inputs}
            if members:
                personal = f"{members[0]}/.dart_tool/personal-notes"
                del names[personal]
                names["member-personal-notes.txt"] = personal
            names.update({"pubspec.lock": "pubspec.lock",
                          "package_config.json": ".dart_tool/package_config.json"})
            for recording_name, project_name in names.items():
                path = project / project_name
                if not path.resolve(strict=True).is_relative_to(project):
                    raise ValueError("generated recording escapes the controlled project")
                data = io.read_file(path)
                destination = case / recording_name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
                files[recording_name] = {"bytes": len(data), "sha256": io.digest(data)}
            sdk_root = sdks[version].parent.parent
            license_bytes = io.read_file(sdk_root / "LICENSE")
            (case / "UPSTREAM-LICENSE").write_bytes(license_bytes)
            files["UPSTREAM-LICENSE"] = {"bytes": len(license_bytes), "sha256": io.digest(license_bytes)}
            receipt = {"schema": "sweepx.generated-format-recording/v1", "tool": "dart pub",
                       "version": version, "sdk": versions[version],
                       "sdkRevision": io.read_file(sdk_root / "revision").decode().strip(),
                       "recordedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
                       "host": {"os": platform.system(), "arch": platform.machine()},
                       "requestedEnvironmentKeys": sorted(env), "generator": "dart pub get --offline",
                       "invocationDirectory": members[0] if members else ".",
                       "removedObsoleteMaps": removed, "scope": "generated format only; report-only",
                       "files": files}
            (case / "receipt.json").write_text(json.dumps(receipt, indent=2, ensure_ascii=False) + "\n",
                                               encoding="utf-8")
            print(f"recorded {case_id}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dart-2", type=Path, required=True, help="Dart 2.18.0 executable")
    parser.add_argument("--dart-3", type=Path, required=True, help="Dart 3.6.0 executable")
    parser.add_argument("--output", type=Path, required=True, help="new directory under an existing parent")
    args = parser.parse_args()
    capture(args.dart_2, args.dart_3, args.output)


if __name__ == "__main__":
    main()
