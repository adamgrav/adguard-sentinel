#!/usr/bin/env python3
"""Check public documentation against the CLI using synthetic loopback services."""

import argparse
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import urllib.parse


REPOSITORY = Path(__file__).resolve().parent.parent
FIXTURES = {
    "/control/status": "status.json",
    "/control/stats": "stats.json",
    "/control/dns_info": "dns-info.json",
    "/control/filtering/status": "filtering-status.json",
    "/control/rewrite/list": "rewrite-list.json",
    "/control/rewrite/settings": "rewrite-settings.json",
}


def run(arguments, **kwargs):
    result = subprocess.run(
        arguments, text=True, capture_output=True, timeout=60, **kwargs
    )
    if result.returncode:
        raise AssertionError(
            f"{arguments!r} exited {result.returncode}\n{result.stdout}{result.stderr}"
        )
    return result.stdout


def blocks(document, language):
    return re.findall(rf"^```{language}\n(.*?)^```", document, re.M | re.S)


def one_matching(items, predicate, description):
    matches = [item for item in items if predicate(item)]
    assert len(matches) == 1, f"expected one {description}, found {len(matches)}"
    return matches[0]


def check_examples(binary):
    readme = (REPOSITORY / "README.md").read_text()
    minimal = one_matching(blocks(readme, "toml"), lambda _: True, "README TOML example")
    assert minimal == (REPOSITORY / "config.minimal.toml").read_text(), (
        "README TOML must match config.minimal.toml"
    )
    walkthrough = one_matching(
        blocks(readme, "sh"), lambda block: "scratch_dir=" in block, "README walkthrough"
    )
    requests = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append((self.command, self.path))
            path = urllib.parse.urlsplit(self.path).path
            if path not in FIXTURES:
                self.send_error(404)
                return
            body = (REPOSITORY / "testdata/api" / FIXTURES[path]).read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="sentinel-doc-check-") as temporary:
            scratch = Path(temporary)
            # Only the resolver address is replaced; the walkthrough itself runs verbatim.
            (scratch / "config.toml").write_text(minimal.replace(
                "https://resolver.example.invalid", f"http://127.0.0.1:{server.server_port}"
            ))
            bin_directory = scratch / "bin"
            bin_directory.mkdir()
            (bin_directory / "adguard-sentinel").symlink_to(binary)
            environment = dict(os.environ, PATH=f"{bin_directory}{os.pathsep}{os.environ['PATH']}",
                               TMPDIR=str(scratch), NO_PROXY="127.0.0.1,localhost",
                               no_proxy="127.0.0.1,localhost")
            marker = scratch / "walkthrough-directory"
            environment["SENTINEL_DOC_CHECK_DIRECTORY"] = str(marker)
            # BSD and GNU mktemp may choose different parents. Capture the documented
            # variable rather than assuming its directory is beneath TMPDIR.
            cleanup = 'trap \'printf "%s\\n" "${scratch_dir:-}" > "$SENTINEL_DOC_CHECK_DIRECTORY"\' EXIT\n'
            try:
                run(["sh", "-eu", "-c", cleanup + walkthrough], cwd=scratch, env=environment)
                walk_directory = Path(marker.read_text().strip()).resolve(strict=True)
                assert walk_directory.name.startswith("tmp."), "unexpected mktemp directory name"
                state = walk_directory / "state.sqlite"
                assert state.is_file(), "walkthrough did not create its state database"
                # Move the whole private directory so all sidecar files remain together.
                retained = scratch / "walkthrough"
                shutil.move(str(walk_directory), retained)
                state = retained / "state.sqlite"
            finally:
                if marker.exists() and marker.read_text().strip():
                    created = Path(marker.read_text().strip())
                    if created.exists():
                        assert created.name.startswith("tmp."), "unexpected mktemp directory name"
                        shutil.rmtree(created)
            report = json.loads(run([str(binary), "report", "--state", str(state),
                                     "--limit", "1", "--format", "json"]))
            assert report["mode"] == "dry_run"
            assert report["complete_targets"] == 1
            assert report["findings"] == []
            assert report["notifications"] == []
            assert sorted(urllib.parse.urlsplit(path).path for _, path in requests) == sorted(FIXTURES)
            assert all(method == "GET" for method, _ in requests)
            before_validation = len(requests)

            def validate(name, text):
                def credential(match):
                    path = scratch / match.group(1)
                    path.write_text("synthetic-secret\n")
                    path.chmod(0o600)
                    return json.dumps(str(path))

                text = re.sub(r'"/run/credentials/adguard-sentinel\.service/([\w-]+)"',
                              credential, text)
                text = re.sub(r'^base_url = "[^"]+"$',
                              f'base_url = "http://127.0.0.1:{server.server_port}"',
                              text, flags=re.M)
                config = scratch / name
                config.write_text(text)
                run([str(binary), "validate-config", "--config", str(config)], env=environment)

            reference = (REPOSITORY / "config.example.toml").read_text()
            validate("reference-disabled.toml", reference)
            enabled = reference.replace('provider = "disabled"', 'provider = "pushover"')
            enabled = re.sub(
                r"^# (\[notifications\.pushover\]|application_token_file = .*|user_key_file = .*)$",
                r"\1", enabled, flags=re.M,
            )
            assert 'provider = "pushover"' in enabled.splitlines()
            assert "[notifications.pushover]" in enabled.splitlines()
            validate("reference-pushover.toml", enabled)
            deployment = blocks((REPOSITORY / "docs/DEPLOYMENT.md").read_text(), "toml")
            basic = one_matching(deployment, lambda block: block.startswith('auth = "basic"'),
                                 "Basic authentication example")
            pushover = one_matching(deployment, lambda block: block.startswith("[notifications]"),
                                    "Pushover example")
            validate("documented-basic.toml", minimal.replace('auth = "none"\n', basic))
            validate("documented-pushover.toml", minimal + "\n" + pushover)
            assert len(requests) == before_validation, "validation contacted the resolver"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    print("PASS: README walkthrough, minimal/reference/authentication/Pushover examples, six synthetic GETs")


def anchors(text):
    text = re.sub(r"^```.*?^```[^\n]*", "", text, flags=re.M | re.S)
    seen = set()
    for heading in re.findall(r"^#{1,6}\s+(.*?)\s*#*\s*$", text, re.M):
        base = re.sub(r"[^\w\s-]", "", heading.lower()).replace(" ", "-")
        anchor = base
        suffix = 0
        while anchor in seen:
            suffix += 1
            anchor = f"{base}-{suffix}"
        seen.add(anchor)
    return seen


def check_links_and_shell():
    tracked = set(run(["git", "ls-files", "-z"], cwd=REPOSITORY).rstrip("\0").split("\0"))
    documents = sorted(path for path in tracked if path.endswith(".md") and (
        "/" not in path or path.startswith(("docs/", "testdata/"))
    ))
    assert documents, "no tracked public Markdown documents found"
    for relative in documents:
        document = REPOSITORY / relative
        text = document.read_text()
        for block in blocks(text, "sh"):
            run(["sh", "-n"], input=block)
        prose = re.sub(r"^```.*?^```[^\n]*", "", text, flags=re.M | re.S)
        for target in re.findall(r"\]\(([^\s)]+)\)", prose):
            parsed = urllib.parse.urlsplit(target)
            if parsed.scheme or parsed.netloc:
                continue
            linked = (document.parent / urllib.parse.unquote(parsed.path)).resolve() if parsed.path else document
            assert linked.is_relative_to(REPOSITORY), (relative, target, "link leaves repository")
            linked_relative = linked.relative_to(REPOSITORY).as_posix()
            present = linked_relative in tracked or (
                linked.is_dir() and any(path.startswith(f"{linked_relative}/") for path in tracked)
            )
            assert present and linked.exists(), (relative, target, "link target is not tracked")
            if parsed.fragment and linked.suffix == ".md":
                assert urllib.parse.unquote(parsed.fragment) in anchors(linked.read_text()), (
                    relative, target, "heading does not exist"
                )
    print(f"PASS: local links, heading anchors, and shell syntax in {len(documents)} tracked public documents")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, help="already-built adguard-sentinel binary")
    arguments = parser.parse_args()
    binary = arguments.binary
    if binary is None:
        metadata = json.loads(run(["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
                                  cwd=REPOSITORY))
        binary = Path(metadata["target_directory"]) / "debug/adguard-sentinel"
    binary = binary.resolve(strict=True)
    check_links_and_shell()
    check_examples(binary)


if __name__ == "__main__":
    main()
