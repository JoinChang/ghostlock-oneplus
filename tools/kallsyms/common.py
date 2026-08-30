#!/usr/bin/env python3
"""Small standard-library helpers shared by the gist scripts."""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Iterator, Mapping, Optional, Sequence, Union


PathLike = Union[str, os.PathLike[str]]


def expanded_path(value: PathLike) -> Path:
    """Expand a user-supplied path without requiring it to exist."""

    return Path(os.path.expandvars(os.path.expanduser(os.fspath(value)))).resolve()


def required_env(name: str) -> Path:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required; set it to the repository path")
    return expanded_path(value)


def configured_url(env_name: str, default: str) -> str:
    return os.environ.get(env_name, default).strip()


def canonical_git_url(value: str) -> str:
    """Normalize the harmless URL differences commonly produced by Git."""

    return value.strip().rstrip("/").removesuffix(".git").lower()


def command_path(value: str) -> Optional[str]:
    """Resolve either a command name or an explicit executable path."""

    expanded = os.path.expandvars(os.path.expanduser(value))
    if os.path.dirname(expanded):
        candidate = Path(expanded)
        return str(candidate) if candidate.is_file() else None
    return shutil.which(expanded)


def first_command(*names: str) -> Optional[str]:
    for name in names:
        found = command_path(name)
        if found:
            return found
    return None


def run(
    command: Sequence[PathLike],
    *,
    cwd: Optional[PathLike] = None,
    env: Optional[Mapping[str, str]] = None,
    capture: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run a command without invoking a shell."""

    argv = [os.fspath(part) for part in command]
    return subprocess.run(
        argv,
        cwd=os.fspath(cwd) if cwd is not None else None,
        env=dict(env) if env is not None else None,
        text=True,
        capture_output=capture,
        check=check,
    )


def output_of(
    command: Sequence[PathLike],
    *,
    cwd: Optional[PathLike] = None,
    env: Optional[Mapping[str, str]] = None,
    check: bool = True,
) -> str:
    return run(command, cwd=cwd, env=env, capture=True, check=check).stdout.strip()


def python_env(repo: Path) -> dict[str, str]:
    env = os.environ.copy()
    old = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(repo) + (os.pathsep + old if old else "")
    return env


def ensure_file(path: Path, description: str) -> None:
    if not path.is_file():
        raise RuntimeError(f"{description} does not exist or is not a file: {path}")
    if path.stat().st_size == 0:
        raise RuntimeError(f"{description} is empty: {path}")


@contextlib.contextmanager
def atomic_output(path: Path, *, suffix: str = ".tmp") -> Iterator[Path]:
    """Yield a temporary sibling and atomically replace the requested path."""

    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=suffix, dir=path.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        yield temporary
        ensure_file(temporary, "temporary output")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
