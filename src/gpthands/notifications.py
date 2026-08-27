from __future__ import annotations

import platform
import shutil
import subprocess
from pathlib import Path


def notify_approval_required(*, workspace: Path, risk: str, action_hash: str) -> bool:
    """Best-effort local desktop notification; never carries secrets or command content."""
    title = "GPTHands approval required"
    body = f"{workspace.name}: {risk} action {action_hash[:12]}…"
    system = platform.system()
    try:
        if system == "Darwin" and shutil.which("osascript"):
            script = 'display notification ' + _apple_quote(body) + ' with title ' + _apple_quote(title)
            return subprocess.run(["osascript", "-e", script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False).returncode == 0
        if system == "Linux" and shutil.which("notify-send"):
            return subprocess.run(["notify-send", title, body], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False).returncode == 0
        if system == "Windows" and shutil.which("powershell.exe"):
            ps = (
                "Add-Type -AssemblyName System.Windows.Forms;"
                "$n=New-Object System.Windows.Forms.NotifyIcon;"
                "$n.Icon=[System.Drawing.SystemIcons]::Shield;"
                "$n.BalloonTipTitle=$env:GPTHANDS_NOTIFY_TITLE;"
                "$n.BalloonTipText=$env:GPTHANDS_NOTIFY_BODY;"
                "$n.Visible=$true;$n.ShowBalloonTip(4000);Start-Sleep -Milliseconds 800;$n.Dispose()"
            )
            env = {"GPTHANDS_NOTIFY_TITLE": title, "GPTHANDS_NOTIFY_BODY": body}
            import os
            merged = dict(os.environ)
            merged.update(env)
            return subprocess.run(
                ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", ps],
                env=merged,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                timeout=5,
            ).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False
    return False


def _apple_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
