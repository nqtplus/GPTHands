from __future__ import annotations

import os
import stat
import time
from pathlib import Path


class LockError(RuntimeError):
    pass


class FileLock:
    """Small cross-platform advisory lock backed by an owner-only regular file."""

    def __init__(self, path: Path, *, timeout: float = 5.0) -> None:
        self.path = path.expanduser()
        self.timeout = timeout
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            try:
                os.chmod(self.path.parent, 0o700)
            except OSError:
                pass
        if self.path.is_symlink():
            raise LockError("lock path must not be a symlink")

        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        self._fd = os.open(self.path, flags, 0o600)
        info = os.fstat(self._fd)
        if not stat.S_ISREG(info.st_mode):
            os.close(self._fd)
            raise LockError("lock path must be a regular file")
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            os.close(self._fd)
            raise LockError("lock file must be owned by current user")
        if os.name != "nt":
            os.fchmod(self._fd, 0o600)
        elif info.st_size == 0:
            os.write(self._fd, b"\0")
            os.fsync(self._fd)
        self._held = False

    def acquire(self) -> None:
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                if os.name == "nt":
                    import msvcrt

                    os.lseek(self._fd, 0, os.SEEK_SET)
                    msvcrt.locking(self._fd, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self._held = True
                return
            except (BlockingIOError, OSError) as exc:
                if time.monotonic() >= deadline:
                    raise LockError(f"timed out acquiring lock: {self.path}") from exc
                time.sleep(0.01)

    def release(self) -> None:
        if not self._held:
            return
        if os.name == "nt":
            import msvcrt

            os.lseek(self._fd, 0, os.SEEK_SET)
            msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(self._fd, fcntl.LOCK_UN)
        self._held = False

    def close(self) -> None:
        fd = getattr(self, "_fd", None)
        if fd is None:
            return
        try:
            self.release()
        finally:
            os.close(fd)
            self._fd = None

    def __enter__(self) -> "FileLock":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()

    def __del__(self) -> None:
        try:
            self.close()
        except OSError:
            pass
