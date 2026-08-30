#!/usr/bin/env python3
"""Clone or fast-forward the source repositories used by the workflow."""

# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from common import (
    canonical_git_url,
    configured_url,
    output_of,
    required_env,
    run,
)


MAGISK_URL = "https://github.com/topjohnwu/Magisk.git"
VMLINUX_TO_ELF_URL = "https://github.com/marin-m/vmlinux-to-elf.git"


def git_output(repo: Path, *arguments: str, check: bool = True) -> str:
    return output_of(["git", "-C", repo, *arguments], check=check)


def is_git_worktree(path: Path) -> bool:
    result = run(
        ["git", "-C", path, "rev-parse", "--is-inside-work-tree"],
        capture=True,
        check=False,
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


def assert_clean(repo: Path) -> None:
    status = git_output(repo, "status", "--porcelain", "--untracked-files=all")
    if status:
        raise RuntimeError(
            f"refusing to update dirty repository {repo}; commit, stash, or remove its changes first"
        )


def sync_repository(path: Path, url: str, *, submodules: bool) -> None:
    """Clone a missing repo; otherwise only fetch and fast-forward it."""

    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        print(f"Cloning {url} -> {path}")
        command = ["git", "clone"]
        if submodules:
            command.append("--recurse-submodules")
        command.extend([url, path])
        run(command)
    else:
        if not path.is_dir():
            raise RuntimeError(f"repository path exists but is not a directory: {path}")
        if not is_git_worktree(path):
            if any(path.iterdir()):
                raise RuntimeError(
                    f"refusing to clone over a non-empty non-Git directory: {path}"
                )
            raise RuntimeError(
                f"{path} is empty but not a Git worktree; remove it yourself or choose another path"
            )

        origin = git_output(path, "config", "--get", "remote.origin.url", check=False)
        if not origin:
            raise RuntimeError(f"{path} has no origin remote")
        if canonical_git_url(origin) != canonical_git_url(url):
            raise RuntimeError(
                f"{path} origin is {origin!r}, expected {url!r}; refusing to update the wrong repository"
            )

        assert_clean(path)
        branch = git_output(path, "symbolic-ref", "--quiet", "--short", "HEAD", check=False)
        if not branch:
            raise RuntimeError(f"{path} is in detached-HEAD state; check out a branch before retrying")

        print(f"Fetching {path}")
        run(["git", "-C", path, "fetch", "--prune", "origin"])

        upstream = git_output(
            path,
            "rev-parse",
            "--abbrev-ref",
            "--symbolic-full-name",
            "@{u}",
            check=False,
        )
        if upstream and not upstream.startswith("origin/"):
            raise RuntimeError(
                f"{path} tracks non-origin upstream {upstream!r}; refusing to merge another remote"
            )
        if not upstream:
            candidate = f"origin/{branch}"
            exists = run(
                ["git", "-C", path, "rev-parse", "--verify", f"refs/remotes/{candidate}"],
                capture=True,
                check=False,
            )
            if exists.returncode != 0:
                raise RuntimeError(
                    f"cannot determine an upstream for {path} branch {branch!r}; set one explicitly"
                )
            upstream = candidate

        print(f"Fast-forwarding {path} to {upstream}")
        run(["git", "-C", path, "merge", "--ff-only", upstream])

    if submodules:
        print(f"Updating submodules in {path}")
        run(["git", "-C", path, "submodule", "update", "--init", "--recursive"])
    assert_clean(path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Clone or fast-forward the analysis repositories and prepare vmlinux-to-elf."
    )
    parser.parse_args()

    if sys.version_info < (3, 9):
        raise RuntimeError(
            f"Python 3.9 or newer is required by vmlinux-to-elf (found {sys.version.split()[0]})"
        )

    magisk = required_env("MAGISK_REPO_DIR")
    vmlinux_to_elf = required_env("VMLINUX_TO_ELF_REPO_DIR")
    magisk_url = configured_url("MAGISK_REPO_URL", MAGISK_URL)
    vmlinux_url = configured_url("VMLINUX_TO_ELF_REPO_URL", VMLINUX_TO_ELF_URL)

    sync_repository(magisk, magisk_url, submodules=True)
    sync_repository(vmlinux_to_elf, vmlinux_url, submodules=False)
    print()
    print("Bootstrap complete.")
    print(f"  Magisk:          {magisk}")
    print(f"  vmlinux-to-elf:  {vmlinux_to_elf}")
    print("  Python/dependencies: managed per invocation by uv script metadata")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"bootstrap: error: {error}", file=sys.stderr)
        raise SystemExit(1)
