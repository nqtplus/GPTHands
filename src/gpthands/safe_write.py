from __future__ import annotations

import errno
import os
import secrets
import stat
import tempfile
from pathlib import Path

from .policy import Policy, PolicyError


def _workspace_relative(policy: Policy, path: Path) -> str:
    try:
        rel = path.resolve(strict=False).relative_to(policy.workspace)
    except ValueError as exc:
        raise PolicyError("write parent escapes workspace") from exc
    text = str(rel)
    return text if text else "."


def _write_fd_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        written = os.write(fd, view[offset:])
        if written <= 0:
            raise OSError("short write while creating atomic file")
        offset += written
    os.fsync(fd)


def _posix_atomic_write(policy: Policy, parent: Path, name: str, data: bytes, *, overwrite: bool) -> None:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        dir_fd = os.open(parent, flags)
    except OSError as exc:
        raise PolicyError(f"cannot securely open write parent: {exc}") from exc

    temp_name = f".gpthands-{secrets.token_hex(16)}"
    temp_created = False
    try:
        parent_info = os.fstat(dir_fd)
        if not stat.S_ISDIR(parent_info.st_mode):
            raise PolicyError("write parent is not a directory")

        try:
            existing = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if stat.S_ISDIR(existing.st_mode):
                raise PolicyError("target is a directory")
            if not overwrite:
                raise PolicyError("target already exists; set overwrite=true explicitly")

        create_flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        create_flags |= getattr(os, "O_CLOEXEC", 0)
        create_flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(temp_name, create_flags, 0o600, dir_fd=dir_fd)
        temp_created = True
        try:
            _write_fd_all(fd, data)
        finally:
            os.close(fd)

        if overwrite:
            # Both source and destination are resolved relative to the already
            # opened directory handle. Replacing the lexical parent with a
            # symlink after validation cannot redirect this commit elsewhere.
            os.replace(temp_name, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            temp_created = False
        else:
            # Hard-linking a regular temp file gives us atomic no-clobber
            # semantics. A target created concurrently yields EEXIST rather than
            # silently turning overwrite=False into an overwrite.
            try:
                os.link(
                    temp_name,
                    name,
                    src_dir_fd=dir_fd,
                    dst_dir_fd=dir_fd,
                    follow_symlinks=False,
                )
            except FileExistsError as exc:
                raise PolicyError("target was created concurrently; refusing to overwrite") from exc
            os.unlink(temp_name, dir_fd=dir_fd)
            temp_created = False

        try:
            os.fsync(dir_fd)
        except OSError as exc:
            # Some filesystems do not support directory fsync. EINVAL/EROFS do
            # not weaken path confinement, but other errors are surfaced.
            if exc.errno not in {errno.EINVAL, errno.EROFS}:
                raise
    finally:
        if temp_created:
            try:
                os.unlink(temp_name, dir_fd=dir_fd)
            except FileNotFoundError:
                pass
        os.close(dir_fd)


def _windows_parent_stable(parent: Path, before: os.stat_result) -> None:
    try:
        resolved = parent.resolve(strict=True)
        after = resolved.stat()
    except OSError as exc:
        raise PolicyError("write parent changed during atomic write") from exc
    if resolved != parent or not os.path.samestat(before, after):
        raise PolicyError("write parent identity changed during atomic write")
    isjunction = getattr(os.path, "isjunction", None)
    if callable(isjunction) and isjunction(parent):
        raise PolicyError("write parent must not be a Windows junction")
    if parent.is_symlink():
        raise PolicyError("write parent must not be a symlink")


def _windows_atomic_write(policy: Policy, parent: Path, path: Path, data: bytes, *, overwrite: bool) -> None:
    # Secure generic commands execute against a private staged AppContainer
    # workspace on Windows, so model-controlled child processes cannot race the
    # host repository path directly. Still revalidate the canonical parent
    # identity immediately before commit and use Windows rename no-clobber
    # semantics when overwrite=False.
    before = parent.stat()
    _windows_parent_stable(parent, before)
    if path.exists() and not overwrite:
        raise PolicyError("target already exists; set overwrite=true explicitly")
    if path.exists() and path.is_dir():
        raise PolicyError("target is a directory")

    fd, temp_name = tempfile.mkstemp(prefix=".gpthands-", dir=parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        _windows_parent_stable(parent, before)
        expected_parent = policy.resolve_path(_workspace_relative(policy, parent), must_exist=True)
        if expected_parent != parent:
            raise PolicyError("write parent canonical path changed during atomic write")
        if overwrite:
            os.replace(temp_name, path)
        else:
            try:
                os.rename(temp_name, path)
            except FileExistsError as exc:
                raise PolicyError("target was created concurrently; refusing to overwrite") from exc
        temp_name = ""
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)


def stable_atomic_write(policy: Policy, path: Path, content: str, *, overwrite: bool) -> None:
    data = content.encode("utf-8")
    if len(data) > policy.max_write_bytes:
        raise PolicyError("content exceeds max_write_bytes")
    if path.name in {"", ".", ".."}:
        raise PolicyError("invalid write target name")

    parent = policy.resolve_path(_workspace_relative(policy, path.parent), must_exist=True)
    if not parent.is_dir():
        raise PolicyError("parent directory does not exist")

    if os.name == "nt":
        _windows_atomic_write(policy, parent, path, data, overwrite=overwrite)
    else:
        _posix_atomic_write(policy, parent, path.name, data, overwrite=overwrite)
