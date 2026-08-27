from __future__ import annotations

import os
import stat
from pathlib import Path


class WindowsPathError(RuntimeError):
    pass


def _is_reparse(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise WindowsPathError(f"cannot inspect staging path: {path}: {exc}") from exc
    attributes = int(getattr(info, "st_file_attributes", 0))
    flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return bool(attributes & flag)


def assert_no_reparse_tree(root: Path) -> None:
    """Reject symlinks, junctions and other reparse points in a staged tree.

    The stable Windows backend is intentionally conservative: an untrusted repo
    that contains a reparse point is not eligible for generic process execution.
    This prevents staging/sync semantics from depending on reparse target ACLs.
    """
    root = root.resolve(strict=True)
    candidates = [root]
    try:
        candidates.extend(root.rglob("*"))
        for path in candidates:
            if _is_reparse(path):
                raise WindowsPathError(f"Windows sandbox refuses reparse point: {path}")
    except OSError as exc:
        raise WindowsPathError(f"cannot scan workspace for reparse points: {exc}") from exc
