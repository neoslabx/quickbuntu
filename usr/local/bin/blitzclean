#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Import packages
import json
import os
import queue
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading

# Import libraries
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List
from typing import Optional
from typing import Tuple
from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QApplication
from PyQt6.QtWidgets import QCheckBox
from PyQt6.QtWidgets import QComboBox
from PyQt6.QtWidgets import QFormLayout
from PyQt6.QtWidgets import QGroupBox
from PyQt6.QtWidgets import QHBoxLayout
from PyQt6.QtWidgets import QLabel
from PyQt6.QtWidgets import QLineEdit
from PyQt6.QtWidgets import QMessageBox
from PyQt6.QtWidgets import QPlainTextEdit
from PyQt6.QtWidgets import QProgressBar
from PyQt6.QtWidgets import QPushButton
from PyQt6.QtWidgets import QSpinBox
from PyQt6.QtWidgets import QVBoxLayout
from PyQt6.QtWidgets import QWidget

# Define 'VERSION'
VERSION = "v4.3-GUI"

# Define 'CONFIG_PATH'
CONFIG_PATH = Path.home() / ".config" / "blitzclean"

# Define 'CONFIG_FILE'
CONFIG_FILE = CONFIG_PATH / "config"


# Class 'SysUtils'
class SysUtils:
    """
    Small collection of system helper utilities used throughout the app.
    Provides time formatting, unit conversion, and free-space queries.
    Designed to be stateless and safe to call from worker threads.
    """

    # Function 'rootcheck'
    @staticmethod
    def rootcheck() -> bool:
        """
        Check if the process is running with root privileges.
        Returns True for root (UID 0) and False otherwise.
        Used to gate system-level cleanup actions.
        """
        return os.geteuid() == 0

    # Function 'now'
    @staticmethod
    def now() -> str:
        """
        Return a HH:MM:SS timestamp string for log messages.
        Uses local system time via datetime.now().
        Keeps log entries consistent and readable.
        """
        return datetime.now().strftime("%H:%M:%S")

    # Function 'unitsize'
    @staticmethod
    def unitsize(num_bytes: int) -> str:
        """
        Convert a byte count to a human-readable size string.
        Scales through KB, MB, GB… using base 1024.
        Always returns a string with two decimal places.
        """
        units = ["Bytes", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"]
        x = float(max(0, int(num_bytes)))
        i = 0
        while x >= 1024 and i < len(units) - 1:
            x /= 1024.0
            i += 1
        return f"{x:.2f} {units[i]}"

    # Function 'freebytes'
    @staticmethod
    def freebytes(path: str) -> int:
        """
        Return the number of free bytes on the filesystem for path.
        Falls back to 0 on errors or missing paths to remain robust.
        Uses os.statvfs for a light-weight, dependency-free call.
        """
        try:
            st = os.statvfs(path)
            return st.f_bavail * st.f_frsize
        except FileNotFoundError:
            return 0
        except PermissionError:
            return 0
        except OSError:
            return 0


# Class 'ShellExec'
class ShellExec:
    """
    Thin subprocess wrapper for running and capturing shell commands.
    Streams output lines to the GUI log for live feedback.
    Centralizes error handling to keep callers simple.
    """

    # Function 'run'
    @staticmethod
    def run(cmd: str, dryrun: bool, logshow) -> int:
        """
        Execute a shell command and stream combined stdout/stderr.
        Honors dry-run mode by only echoing the command to the log.
        Returns the subprocess return code (0 on success).
        """
        if dryrun:
            logshow(f"[Dry-Run] {cmd}")
            return 0
        logshow(f"$ {cmd}")
        try:
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in iter(proc.stdout.readline, ""):
                if not line:
                    break
                logshow(line.rstrip())
            proc.wait()
            return proc.returncode
        except (OSError, subprocess.SubprocessError) as e:
            logshow(f"[!] Failed to run: {cmd} -> {e}")
            return 1

    # Function 'capture'
    @staticmethod
    def capture(cmd: str) -> Tuple[int, str]:
        """
        Run a command and capture its entire output as text.
        Returns (exit_code, output) without raising exceptions.
        Keeps callers resilient to command failures.
        """
        try:
            out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
            return 0, out
        except subprocess.CalledProcessError as e:
            return e.returncode, e.output
        except (OSError, subprocess.SubprocessError) as e:
            return 1, str(e)


# Class 'FileOps'
class FileOps:
    """
    File and directory operations with size accounting.
    Implements safe removal, tree wiping, and glob deletions.
    Designed to work in dry-run mode for previews.
    """

    # Function 'removefile'
    @staticmethod
    def removefile(path: Path, dryrun: bool, logshow) -> int:
        """
        Remove a file (or try to remove a path) and return freed bytes.
        Honors dry-run by logging the target without deleting it.
        Handles directories, permissions, and errors gracefully.
        """
        try:
            if not path.exists():
                return 0
            size = path.stat().st_size if path.is_file() else 0
            logshow(str(path))

            if dryrun:
                return size
            try:
                path.unlink(missing_ok=True)
            except IsADirectoryError:
                shutil.rmtree(path, ignore_errors=True)
                size = 0
            except PermissionError:
                ShellExec.run(f"rm -f {shlex.quote(str(path))}", dryrun=False, logshow=logshow)
            return size
        except OSError as e:
            logshow(f"[!] remove file failed: {path} -> {e}")
            return 0

    # Function 'removetree'
    @staticmethod
    def removetree(path: Path, dryrun: bool, logshow) -> int:
        """
        Recursively remove a directory tree and return total bytes.
        In dry-run, lists the tree contents to be removed.
        Continues past unreadable files to maximize coverage.
        """
        try:
            if not path.exists():
                return 0
            total = 0
            for p in path.rglob("*"):
                try:
                    if p.is_file():
                        total += p.stat().st_size
                except (OSError, PermissionError, FileNotFoundError):
                    pass

            logshow(str(path))
            for p in path.rglob("*"):
                logshow(str(p))

            if dryrun:
                return total
            shutil.rmtree(path, ignore_errors=True)
            return total
        except OSError as e:
            logshow(f"[!] remove tree failed: {path} -> {e}")
            return 0

    # Function 'wipedir'
    @staticmethod
    def wipedir(path: Path, dryrun: bool, logshow) -> int:
        """
        Delete all items inside a directory, keeping the directory itself.
        Returns the estimated bytes freed by removed items.
        Useful for cache folders that must persist.
        """
        if not path.exists() or not path.is_dir():
            return 0
        total = 0
        try:
            for item in path.iterdir():
                if item.is_dir():
                    total += FileOps.removetree(item, dryrun, logshow)
                else:
                    total += FileOps.removefile(item, dryrun, logshow)
            return total
        except OSError as e:
            logshow(f"[!] wipe dir failed: {path} -> {e}")
            return 0

    # Function 'globdel'
    @staticmethod
    def globdel(dirpath: Path, pattern: str, dryrun: bool, logshow) -> int:
        """
        Delete files under dirpath matching a recursive glob pattern.
        Returns the sum of bytes accounted for removed files.
        Logs directories in dry-run to preview scope.
        """
        if not dirpath.exists() or not dirpath.is_dir():
            return 0
        total = 0
        try:
            for p in dirpath.rglob(pattern):
                if p.is_file():
                    total += FileOps.removefile(p, dryrun, logshow)
                elif dryrun and p.is_dir():
                    logshow(str(p))
            return total
        except OSError as e:
            logshow(f"[!] glob delete failed: {dirpath} {pattern} -> {e}")
            return 0


# Class 'UserDiscovery'
class UserDiscovery:
    """
    Utilities to discover candidate user accounts to clean.
    Enumerates /root and directories under /home.
    Sorts with the current user (if known) first for convenience.
    """

    # Function 'listusers'
    @staticmethod
    def listusers() -> List[Tuple[str, str]]:
        """
        Return a list of (username, home_path) tuples to populate the UI.
        Includes root when /root exists and all folders under /home.
        Prioritizes the invoking user in the returned ordering.
        """
        users: List[Tuple[str, str]] = []
        if os.path.isdir("/root"):
            users.append(("root", "/root"))
        homedir = Path("/home")
        if homedir.is_dir():
            for child in sorted(homedir.iterdir()):
                if child.is_dir():
                    users.append((child.name, str(child)))
        current = os.environ.get("SUDO_USER") or os.environ.get("USER") or ""
        users.sort(key=lambda t: (t[0] != current, t[0]))
        return users


# Class 'ConfigManager'
class ConfigManager:
    """
    Load and save persistent options to a simple key=value file.
    Stores preferences in ~/.config/blitzclean/config.
    Keeps the GUI state across restarts (e.g., toggles and values).
    """

    # Function 'load'
    @staticmethod
    def load() -> dict:
        """
        Read the config file and return a dict of string keys/values.
        Ignores blank lines, comments, and malformed entries.
        Fails silently for robustness if the file is unreadable.
        """
        data = {}
        try:
            if CONFIG_FILE.is_file():
                for line in CONFIG_FILE.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    data[k.strip()] = v.strip()
        except (OSError, UnicodeDecodeError):
            pass
        return data

    # Function 'save'
    @staticmethod
    def save(opts: "ExecOpts", bootrun: bool, shutrun: bool):
        """
        Persist the provided options and run flags to disk.
        Creates the config directory if it does not exist.
        Overwrites the file atomically by writing complete content.
        """
        try:
            CONFIG_PATH.mkdir(parents=True, exist_ok=True)
            lines = [
                f"dryrun={'1' if opts.dryrun else '0'}",
                f"clearbrowsers={'1' if opts.clearbrowsers else '0'}",
                f"clearkernels={'1' if opts.clearkernels else '0'}",
                f"vacuumdays={opts.vacuumdays}",
                f"vacuumsize={opts.vacuumsize}",
                f"keepsnaps={opts.keepsnaps}",
                f"shutafter={'1' if opts.shutafter else '0'}",
                f"username={opts.username}",
                f"userhome={opts.userhome}",
                f"bootrun={'1' if bootrun else '0'}",
                f"shutrun={'1' if shutrun else '0'}",
                f"aggressive={'1' if opts.aggressive else '0'}",
            ]

            CONFIG_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
        except OSError:
            pass


# Class 'ExecOpts'
@dataclass
class ExecOpts:
    """
    Strongly-typed container for execution options selected in the UI.
    Passed to the worker to control behavior (dry-run, kernels, etc.).
    Serializable to the on-disk config via ConfigManager.
    """

    dryrun: bool = False
    clearbrowsers: bool = False
    clearkernels: bool = False
    vacuumdays: int = 7
    vacuumsize: str = "100M"
    keepsnaps: int = 2
    shutafter: bool = False
    username: str = ""
    userhome: str = ""
    aggressive: bool = False

    # Function 'todict'
    def todict(self) -> dict:
        """
        Serialize the current execution options to a plain dictionary.
        Keeps only JSON-safe primitives for safe transport across processes.
        Used by the privileged worker mode invoked through 'pkexec'.
        """
        return {
            "dryrun": self.dryrun,
            "clearbrowsers": self.clearbrowsers,
            "clearkernels": self.clearkernels,
            "vacuumdays": self.vacuumdays,
            "vacuumsize": self.vacuumsize,
            "keepsnaps": self.keepsnaps,
            "shutafter": self.shutafter,
            "username": self.username,
            "userhome": self.userhome,
            "aggressive": self.aggressive,
        }

    # Function 'fromdict'
    @staticmethod
    def fromdict(d: dict) -> "ExecOpts":
        """
        Build an ExecOpts instance from a dictionary of values.
        Applies defensive casting and reasonable defaults to each field.
        Used by the headless worker to reconstruct options from JSON.
        """
        return ExecOpts(
            dryrun=bool(d.get("dryrun", False)),
            clearbrowsers=bool(d.get("clearbrowsers", False)),
            clearkernels=bool(d.get("clearkernels", False)),
            vacuumdays=int(d.get("vacuumdays", 7)),
            vacuumsize=str(d.get("vacuumsize", "100M")),
            keepsnaps=int(d.get("keepsnaps", 2)),
            shutafter=bool(d.get("shutafter", False)),
            username=str(d.get("username", "")),
            userhome=str(d.get("userhome", "")),
            aggressive=bool(d.get("aggressive", False)),
        )


# Class 'SysCleaner'
class SysCleaner:
    """
    Core cleaner that performs home and system cleanup tasks.
    Accumulates estimated/recovered bytes for summary reporting.
    Supports cooperative cancellation via a stop flag.
    """

    # Function '__init__'
    def __init__(self, opts: ExecOpts, logshow):
        """
        Initialize the cleaner with options and a logging callback.
        Tracks before/after free space to compute recovered bytes.
        Designed to run inside a background thread.
        """
        self.opts = opts
        self.log = logshow
        self.totalbytes = 0
        self.frontroot = 0
        self.fronthome = 0
        self.backroot = 0
        self.backhome = 0
        self.stopflag = False

    # Function 'stop'
    def stop(self):
        """
        Request a cooperative stop of the running cleanup.
        Sets a boolean flag that is checked between steps.
        Raises no exception itself and returns immediately.
        """
        self.stopflag = True

    # Function 'addbytes'
    def addbytes(self, n: int):
        """
        Safely add a numeric byte count to the running total.
        Guards against bad types or overflow with a try/except.
        Used to provide estimates in dry-run mode.
        """
        try:
            self.totalbytes += int(n)
        except (ValueError, TypeError, OverflowError):
            pass

    # Function 'banner'
    def banner(self):
        """
        Print a header describing mode, options, and privileges.
        Helps the user understand what will be executed.
        Logged at the start of each cleanup run.
        """
        self.log("=" * 80)
        self.log(f"BlitzClean {VERSION} - Ubuntu Cleanup GUI")
        self.log("=" * 80)
        mode = "dry-run (listing only)" if self.opts.dryrun else "real execution"
        self.log(f"[+] Mode {mode}")

        if self.opts.clearbrowsers:
            self.log("[+] Browser cache cleaning enabled")

        if self.opts.clearkernels:
            self.log("[+] Kernel removal enabled")

        if self.opts.aggressive:
            self.log("[+] Aggressive app data cleanup ENABLED (risky)")

        self.log(f"[+] Journal retention {self.opts.vacuumdays} days / {self.opts.vacuumsize} max size")
        self.log("[+] Privileges root" if SysUtils.rootcheck() else "[+] Privileges user-only")

    # Function 'checkstop'
    def checkstop(self):
        """
        Raise a RuntimeError when a stop is requested.
        Called at safe points between cleanup phases.
        Allows the GUI to cancel long operations responsively.
        """
        if self.stopflag:
            raise RuntimeError("Operation cancelled by user.")

    # Function 'cleanupuser'
    def cleanupuser(self, uh: Path):
        """
        Clean a specific user's home directory tree.
        Wipes caches, histories, recents, and browser artifacts.
        Honors dry-run mode and accounts for estimated freed bytes.
        """
        self.log("-" * 80)
        self.log(f"[+] Cleaning {uh} user data")
        targets = [
            ".cache/babl",
            ".cache/easytag",
            ".cache/gimp",
            ".cache/JetBrains",
            ".cache/keepassxc",
            ".cache/Microsoft",
            ".cache/obexd",
            ".cache/shotwell",
            ".cache/shutter",
            ".cache/sublime-text",
            ".cache/thumbnails",
            ".cache/totem",
            ".cache/tracker3",
            ".cache/ubuntu-report",
            ".cache/fontconfig",
            ".cache/mesa_shader_cache",
            ".cache/pip",
            ".cache/npm",
            ".cache/yarn",
            ".cache/pnpm",
            ".cache/thunderbird",
            ".cache/vscode",
            ".config/Code/Cache",
            ".config/Code/CachedData",
            ".config/Code/logs",
            ".cache/discord",
            ".config/discord/Cache",
            ".config/discord/Code Cache",
            ".profile.bak",
            ".shell.pre-oh-my-zsh",
            ".shutter",
            ".thumbnails",
            ".wget-hsts",
            ".zcompdump",
            ".zshrc.bak",
        ]

        for rel in targets:
            self.checkstop()
            p = uh / rel
            if p.is_dir():
                self.addbytes(FileOps.wipedir(p, self.opts.dryrun, self.log))
            else:
                self.addbytes(FileOps.removefile(p, self.opts.dryrun, self.log))

        for p in uh.glob(".zcompdump-*"):
            self.checkstop()
            self.addbytes(FileOps.removefile(p, self.opts.dryrun, self.log))

        flatpakroot = uh / ".var" / "app"
        if flatpakroot.is_dir():
            self.log("-" * 80)
            self.log("[+] Cleaning Flatpak user caches (~/.var/app/*/cache)")
            for appdir in flatpakroot.iterdir():
                if not appdir.is_dir():
                    continue
                cache_dir = appdir / "cache"
                if cache_dir.exists():
                    self.addbytes(FileOps.wipedir(cache_dir, self.opts.dryrun, self.log))

        self.log("-" * 80)
        self.log("[+] Emptying trash")
        if shutil.which("trash-empty"):
            ShellExec.run("trash-empty --all-users -v -f", self.opts.dryrun, self.log)
        else:
            self.log("trash-empty not found")

        self.log("-" * 80)
        self.log("[+] Cleaning recent documents")
        recent = [
            ".cache/recently-used.xbel",
            ".local/share/RecentDocuments",
            ".local/share/recently-used.xbel"
        ]

        for rel in recent:
            self.checkstop()
            p = uh / rel
            if p.is_file():
                self.addbytes(FileOps.removefile(p, self.opts.dryrun, self.log))
            elif p.is_dir():
                self.addbytes(FileOps.globdel(p, "*.desktop", self.opts.dryrun, self.log))

        if self.opts.clearbrowsers:
            self.log("-" * 80)
            self.log("[+] Cleaning browser caches")
            ffroot = uh / ".mozilla" / "firefox"

            if ffroot.is_dir():
                for prof in ffroot.glob("*.default*"):
                    self.checkstop()
                    self.addbytes(FileOps.wipedir(prof / "cache2", self.opts.dryrun, self.log))
                    self.addbytes(FileOps.wipedir(prof / "startupCache", self.opts.dryrun, self.log))

            for rel in [
                ".cache/google-chrome",
                ".cache/chromium",
                ".config/google-chrome",
                ".config/BraveSoftware/Brave-Browser/Default/Cache",
                ".config/BraveSoftware/Brave-Browser/Default/Code Cache",
                ".config/chromium/Default/Cache",
                ".config/chromium/Default/Code Cache",
            ]:
                self.checkstop()
                p = uh / rel
                if p.is_dir():
                    self.addbytes(FileOps.wipedir(p, self.opts.dryrun, self.log))

        self.log("-" * 80)
        self.log(f"[+] Cleaning {uh} shell history")
        for rel in [".bash_history", ".zsh_history"]:
            self.checkstop()
            p = uh / rel
            if self.opts.dryrun:
                if p.exists():
                    self.log(str(p))
            else:
                try:
                    if p.exists():
                        with open(p, "w", encoding="utf-8") as f:
                            f.write("")
                        os.chmod(p, 0o600)
                        self.log(str(p))
                except OSError as e:
                    self.log(f"[!] history wipe failed: {p} -> {e}")

        if self.opts.aggressive:
            self.log("-" * 80)
            self.log("[!] Aggressive: removing user app data (may affect apps)")
            snapdir = uh / "snap"
            if snapdir.exists():
                self.log(f"[+] Removing {snapdir}")
                self.addbytes(FileOps.removetree(snapdir, self.opts.dryrun, self.log))
            sshdir = uh / ".ssh"
            if sshdir.exists():
                self.log(f"[+] Removing {sshdir}")
                self.addbytes(FileOps.removetree(sshdir, self.opts.dryrun, self.log))

    # Function 'cleanuphome'
    def cleanuphome(self):
        """
        Clean user-level caches, histories, and recent documents.
        Optionally clears browser caches when enabled.
        Updates estimated bytes freed for summary reporting.
        """
        self.cleanupuser(Path(self.opts.userhome))

    # Function 'cleanupsystem'
    def cleanupsystem(self):
        """
        Perform privileged system cleanup for caches, logs, and packages.
        Requires root; otherwise the function exits early.
        Includes journal vacuuming, snap/flatpak pruning, and kernels.
        """
        if not SysUtils.rootcheck():
            return

        self.log("-" * 80)
        self.log("[+] Cleaning system directories")
        self.addbytes(FileOps.wipedir(Path("/tmp"), self.opts.dryrun, self.log))
        self.addbytes(FileOps.wipedir(Path("/var/tmp"), self.opts.dryrun, self.log))
        ShellExec.run("apt-get -y autoremove --purge", self.opts.dryrun, self.log)
        ShellExec.run("apt-get -y autoclean", self.opts.dryrun, self.log)
        ShellExec.run("apt-get -y clean", self.opts.dryrun, self.log)
        self.addbytes(FileOps.globdel(Path("/var/crash"), "*.crash", self.opts.dryrun, self.log))
        self.addbytes(FileOps.globdel(Path("/var/log"), "*.gz", self.opts.dryrun, self.log))
        self.addbytes(FileOps.globdel(Path("/var/log"), "*.[0-9]", self.opts.dryrun, self.log))
        ShellExec.run(f"journalctl --vacuum-time={self.opts.vacuumdays}d", self.opts.dryrun, self.log)
        ShellExec.run(f"journalctl --vacuum-size={self.opts.vacuumsize}", self.opts.dryrun, self.log)
        ShellExec.run(f"snap set system refresh.retain={self.opts.keepsnaps}", self.opts.dryrun, self.log)

        if self.opts.dryrun:
            self.log("[Dry-Run] remove disabled snap revisions")
        else:
            cmd = r"snap list --all 2>/dev/null | awk '/disabled/ {print $1, $3}'"
            ec, out = ShellExec.capture(cmd)
            if ec == 0 and out.strip():
                for line in out.strip().splitlines():
                    parts = line.split()
                    if len(parts) != 2:
                        continue
                    name, rev = parts
                    ShellExec.run(f"snap remove --revision={shlex.quote(rev)} {shlex.quote(name)} --purge", False, self.log)

        self.addbytes(FileOps.wipedir(Path("/var/cache/fontconfig"), self.opts.dryrun, self.log))
        self.addbytes(FileOps.wipedir(Path("/var/cache/man"), self.opts.dryrun, self.log))
        self.addbytes(FileOps.wipedir(Path("/var/lib/systemd/coredump"), self.opts.dryrun, self.log))
        self.addbytes(FileOps.wipedir(Path("/var/lib/snapd/cache"), self.opts.dryrun, self.log))
        ShellExec.run("flatpak uninstall --unused -y", self.opts.dryrun, self.log)

        if self.opts.dryrun:
            self.log("[Dry-Run] deborphan | apt-get remove --purge -y")
        else:
            cmd = "deborphan 2>/dev/null"
            ec, out = ShellExec.capture(cmd)
            if ec == 0 and out.strip():
                pkgs = " ".join(shlex.quote(x) for x in out.strip().splitlines())
                ShellExec.run(f"apt-get remove --purge -y {pkgs}", False, self.log)

        if self.opts.clearkernels:
            self.log("-" * 80)
            cur_kernel = self.kernelnow()
            self.log(f"[+] Removing old kernels (current: {cur_kernel})")
            pkgs = self.kernelold(cur_kernel)
            for pkg in pkgs:
                ShellExec.run(f"apt-get remove --purge -y {shlex.quote(pkg)}", self.opts.dryrun, self.log)
            ShellExec.run("update-grub", self.opts.dryrun, self.log)

        self.log("-" * 80)
        self.log("[+] Cleaning root data")
        for p in ["/root/.cache", "/root/.config", "/root/.launchpadlib", "/root/.wget-hsts"]:
            self.log(p)
            path = Path(p)
            if path.is_dir():
                self.addbytes(FileOps.wipedir(path, self.opts.dryrun, self.log))
            else:
                self.addbytes(FileOps.removefile(path, self.opts.dryrun, self.log))

        self.log("-" * 80)
        self.log("[+] Cleaning root shell history")
        if self.opts.dryrun:
            self.log("/root/.history")
        else:
            try:
                Path("/root/.history").write_text("")
            except OSError:
                pass
            ShellExec.run("history -c && history -w", self.opts.dryrun, self.log)

    # Function 'kernelnow'
    @staticmethod
    def kernelnow() -> str:
        """
        Return the current kernel version string (without -generic).
        Uses uname -r and strips the common suffix for matching.
        Falls back to empty string when detection fails.
        """
        ec, out = ShellExec.capture("uname -r | sed 's/-generic//'")
        if ec == 0:
            return out.strip()
        return ""

    # Function 'kernelold'
    @staticmethod
    def kernelold(current_kernel: str) -> List[str]:
        """
        List installed linux-image packages excluding the current kernel.
        Parses dpkg -l output for linux-image entries.
        Returns package names suitable for apt removal.
        """
        ec, out = ShellExec.capture("dpkg -l | awk '/^ii\\s+linux-image-[0-9]/{print $2}'")
        pkgs = []
        if ec == 0:
            for line in out.strip().splitlines():
                if current_kernel and current_kernel in line:
                    continue
                pkgs.append(line.strip())
        return pkgs

    # Function 'run'
    def run(self):
        """
        Orchestrate the full cleanup flow and error handling.
        Measures free space before/after to compute recovery.
        Optionally schedules an immediate shutdown when done.
        """
        self.banner()
        self.frontroot = SysUtils.freebytes("/")
        self.fronthome = SysUtils.freebytes(self.opts.userhome)

        try:
            if SysUtils.rootcheck():
                self.log("-" * 80)
                self.log("[+] Running as root: cleaning all users")
                homes = [("root", "/root")]
                homes.extend(UserDiscovery.listusers())
                seen = set()
                for _, home in homes:
                    if home in seen:
                        continue
                    seen.add(home)
                    self.checkstop()
                    self.cleanupuser(Path(home))
                self.checkstop()
                self.cleanupsystem()
            else:
                self.cleanuphome()
                self.checkstop()
                self.cleanupsystem()
        except RuntimeError as e:
            self.log(f"[!] {e}")
        except (OSError, PermissionError, subprocess.SubprocessError, ValueError) as e:
            self.log(f"[!] Unexpected error: {e}")

        self.summary()
        if self.opts.shutafter and not self.opts.dryrun:
            self.log("Scheduling shutdown now...")
            ShellExec.run("shutdown now", False, self.log)

    # Function 'summary'
    def summary(self):
        """
        Print a human-readable summary of bytes freed.
        Shows estimates in dry-run and actual deltas otherwise.
        Separates results for root partition and home path.
        """
        self.log("=" * 80)
        self.log("Cleanup Summary")
        self.log("=" * 80)
        if self.opts.dryrun:
            self.log(f"[+] Estimated freed: {SysUtils.unitsize(self.totalbytes)}")
            self.log("[+] Dry-run mode")
        else:
            self.backroot = SysUtils.freebytes("/")
            self.backhome = SysUtils.freebytes(self.opts.userhome)
            dr = self.backroot - self.frontroot
            dh = self.backhome - self.fronthome
            self.log(f"[+] Recovered on / : {SysUtils.unitsize(dr)}")
            self.log(f"[+] Recovered on ~ : {SysUtils.unitsize(dh)}")


# Class 'BlitzClean'
class BlitzClean(QWidget):
    """
    PyQt6 main window wiring the UI to the cleaner worker.
    Handles configuration, logging, and thread lifecycle.
    Provides a responsive experience with a progress indicator.
    """

    # Function '__init__'
    def __init__(self):
        """
        Build the UI, wire signals, and start the log flusher timer.
        Loads saved configuration to restore previous state.
        Prepares a background thread for cleanup execution.
        """
        super().__init__()
        self.setWindowTitle(f"BlitzClean {VERSION} - Ubuntu Cleanup GUI")
        self.resize(980, 720)

        # Inputs
        self.cb_dry = QCheckBox("Dry-run (preview only)")
        self.cb_browsers = QCheckBox("Clean browser caches (Firefox/Chrome/Chromium/Brave)")
        self.cb_kernels = QCheckBox("Remove old kernels (keeps current)")
        self.cb_shutdown = QCheckBox("Shutdown after cleanup")
        self.cb_run_boot = QCheckBox("Run at boot")
        self.cb_run_shutdown = QCheckBox("Run at shutdown")
        self.cb_aggressive = QCheckBox("Aggressive app data cleanup (risky)")

        self.spin_days = QSpinBox()
        self.spin_days.setRange(0, 3650)
        self.spin_days.setValue(7)

        self.edit_size = QLineEdit("100M")
        self.spin_keep = QSpinBox()
        self.spin_keep.setRange(1, 10)
        self.spin_keep.setValue(2)

        self.cmb_user = QComboBox()
        self.users = UserDiscovery.listusers()
        for u, home in self.users:
            self.cmb_user.addItem(f"{u}  —  {home}", (u, home))

        # Buttons
        self.btn_run = QPushButton("Run")
        self.btn_stop = QPushButton("Stop")
        self.btn_stop.setEnabled(False)

        # Log
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        font = QFont("Monospace")
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.log.setFont(font)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setVisible(False)

        # Layouts
        form_box = QGroupBox("Options")
        form = QFormLayout()
        form.addRow(self.cb_dry)
        form.addRow(self.cb_browsers)
        form.addRow(self.cb_kernels)
        form.addRow(self.cb_shutdown)
        form.addRow(self.cb_run_boot)
        form.addRow(self.cb_run_shutdown)
        form.addRow(self.cb_aggressive)
        form.addRow(QLabel("Journal vacuum days:"), self.spin_days)
        form.addRow(QLabel("Journal vacuum size:"), self.edit_size)
        form.addRow(QLabel("Keep Snap revisions:"), self.spin_keep)
        form.addRow(QLabel("User to clean:"), self.cmb_user)
        form_box.setLayout(form)

        btn_row = QHBoxLayout()
        btn_row.addWidget(self.btn_run)
        btn_row.addWidget(self.btn_stop)
        btn_row.addStretch()
        btn_row.addWidget(self.progress)

        layout = QVBoxLayout()
        layout.addWidget(form_box)
        layout.addLayout(btn_row)
        layout.addWidget(QLabel("Output:"))
        layout.addWidget(self.log, stretch=1)
        self.setLayout(layout)

        # State
        self.worker_thread = None
        self.cleaner: Optional[SysCleaner] = None
        self.log_queue = queue.Queue()

        # Signals
        self.btn_run.clicked.connect(self.onrun)
        self.btn_stop.clicked.connect(self.onstop)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.logflush)
        self.timer.start(100)

        # Load config on startup
        self.confloader()

    # Function 'confloader'
    def confloader(self):
        """
        Read saved settings from disk and update UI controls.
        Converts string flags and numbers with defensive parsing.
        Restores previously selected user when available.
        """
        cfg = ConfigManager.load()

        def b(key, default=False):
            return cfg.get(key, "1" if default else "0") in ("1", "true", "True", "yes")

        def s(key, default=""):
            return cfg.get(key, default)

        self.cb_dry.setChecked(b("dryrun", False))
        self.cb_browsers.setChecked(b("clearbrowsers", False))
        self.cb_kernels.setChecked(b("clearkernels", False))
        self.cb_shutdown.setChecked(b("shutafter", False))
        self.cb_run_boot.setChecked(b("bootrun", False))
        self.cb_run_shutdown.setChecked(b("shutrun", False))
        self.cb_aggressive.setChecked(b("aggressive", False))

        try:
            self.spin_days.setValue(int(cfg.get("vacuumdays", "7")))
        except (ValueError, TypeError):
            pass
        self.edit_size.setText(s("vacuumsize", "100M"))
        try:
            self.spin_keep.setValue(int(cfg.get("keepsnaps", "2")))
        except (ValueError, TypeError):
            pass

        saved_user = s("username", "")
        for i in range(self.cmb_user.count()):
            u, _ = self.cmb_user.itemData(i)
            if u == saved_user:
                self.cmb_user.setCurrentIndex(i)
                break

    # Function 'confpersist'
    def confpersist(self, opts: ExecOpts):
        """
        Save current UI options to the user config path.
        Persists run-at-boot/shutdown toggles alongside options.
        Called right before launching the background worker.
        """
        ConfigManager.save(opts, self.cb_run_boot.isChecked(), self.cb_run_shutdown.isChecked())

    # Function 'logappend'
    def logappend(self, text: str):
        """
        Append a timestamped line to the visible log widget.
        Auto-scrolls to the bottom to keep latest entries visible.
        Thread-safe via a queue drained on a QTimer tick.
        """
        ts = SysUtils.now()
        self.log.appendPlainText(f"[{ts}] {text}")
        self.log.verticalScrollBar().setValue(self.log.verticalScrollBar().maximum())

    # Function 'logshow'
    def logshow(self, text: str):
        """
        Enqueue a log line to be flushed by the GUI timer.
        Keeps worker threads decoupled from UI updates.
        Prevents cross-thread access to Qt widgets.
        """
        self.log_queue.put(text)

    # Function 'logflush'
    def logflush(self):
        """
        Drain the queued log lines and paint them into the widget.
        Called periodically by a QTimer to keep UI responsive.
        Silently returns when the queue is empty.
        """
        try:
            while True:
                msg = self.log_queue.get_nowait()
                self.logappend(msg)
        except queue.Empty:
            pass

    # Function 'gatheropts'
    def gatheropts(self) -> ExecOpts:
        """
        Read UI controls and create a populated ExecOpts instance.
        Strips/normalizes text inputs and clamps numeric fields.
        Returns a ready-to-use options object for the worker.
        """
        user, home = self.cmb_user.currentData()
        return ExecOpts(
            dryrun=self.cb_dry.isChecked(),
            clearbrowsers=self.cb_browsers.isChecked(),
            clearkernels=self.cb_kernels.isChecked(),
            vacuumdays=self.spin_days.value(),
            vacuumsize=self.edit_size.text().strip() or "100M",
            keepsnaps=self.spin_keep.value(),
            shutafter=self.cb_shutdown.isChecked(),
            username=user,
            userhome=home,
            aggressive=self.cb_aggressive.isChecked(),
        )

    # Function 'rootlauncher'
    def rootlauncher(self) -> bool:
        """
        Attempt to relaunch this program via pkexec for elevation.
        Spawns a new elevated process and exits the current GUI.
        Shows a helpful error when policykit is unavailable.
        """
        if shutil.which("pkexec"):
            try:
                args = [sys.executable, sys.argv[0], *sys.argv[1:]]
                subprocess.Popen(["pkexec", *args])
                QApplication.quit()
                return True
            except (OSError, subprocess.SubprocessError):
                pass
        QMessageBox.critical(
            self,
            "Elevation failed",
            "Could not escalate privileges. Please install 'policykit-1' (pkexec) or run this app as root."
        )
        return False

    # Function 'startworker'
    def startworker(self, opts: ExecOpts):
        """
        Start the cleaner in a background daemon thread.
        Disables the Run button, enables Stop, and shows progress.
        Ensures UI state is restored when the worker completes.
        """
        if self.worker_thread and self.worker_thread.is_alive():
            QMessageBox.warning(self, "Busy", "A cleanup task is already running.")
            return

        self.progress.setVisible(True)
        self.btn_stop.setEnabled(True)
        self.btn_run.setEnabled(False)
        self.confpersist(opts)
        rootneed = (opts.username == "root") and not SysUtils.rootcheck()

        # Function 'workload'
        def workload():
            """
            Worker thread target calling the cleaner pipeline.
            Guarantees UI toggles are reset even on exceptions.
            Posts a terminal marker to the log queue when finished.
            """
            try:
                if rootneed:
                    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tf:
                        tf.write(json.dumps(opts.todict()))
                        tf.flush()
                        optsfile = tf.name
                    try:
                        cmd = ["pkexec", sys.executable, sys.argv[0], "--worker", optsfile]
                        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                        for line in iter(proc.stdout.readline, ""):
                            if not line:
                                break
                            self.logshow(line.rstrip())
                        proc.wait()
                    finally:
                        try:
                            os.unlink(optsfile)
                        except OSError:
                            pass
                else:
                    self.cleaner = SysCleaner(opts, self.logshow)
                    self.cleaner.run()
            finally:
                self.log_queue.put("--- Done ---")
                self.progress.setVisible(False)
                self.btn_stop.setEnabled(False)
                self.btn_run.setEnabled(True)

        self.worker_thread = threading.Thread(target=workload, daemon=True)
        self.worker_thread.start()

    # Function 'onrun'
    def onrun(self):
        """
        Gather options and kick off a new cleanup session.
        Clears any previous output and pending log messages first.
        Offers elevation if the selected target user is root.
        """
        self.log.clear()
        try:
            while True:
                self.log_queue.get_nowait()
        except queue.Empty:
            pass

        opts = self.gatheropts()
        self.startworker(opts)

    # Function 'onstop'
    def onstop(self):
        """
        Request cancellation of the running cleanup task.
        Disables the Stop button to prevent duplicate clicks.
        The worker will exit at the next safe checkpoint.
        """
        if self.cleaner:
            self.cleaner.stop()
            self.logappend("Stop requested...")
            self.btn_stop.setEnabled(False)


# Class 'App'
class App:
    """
    Simple application bootstrap wrapper for Qt.
    Creates the main window and enters the event loop.
    Keeps __main__ clean and import-friendly.
    """

    # Function 'main'
    @staticmethod
    def main():
        """
        Initialize QApplication and show BlitzClean window.
        Exits with the Qt application return code.
        Provides a single entry point for CLI execution.
        """
        if len(sys.argv) == 3 and sys.argv[1] == "--worker":
            opts_path = Path(sys.argv[2])
            data = json.loads(opts_path.read_text(encoding="utf-8"))
            opts = ExecOpts.fromdict(data)

            def logshow(line: str):
                print(line, flush=True)

            cleaner = SysCleaner(opts, logshow)
            cleaner.run()
            return 0

        app = QApplication(sys.argv)
        win = BlitzClean()
        win.show()
        sys.exit(app.exec())


# Main callback
if __name__ == "__main__":
    App.main()
