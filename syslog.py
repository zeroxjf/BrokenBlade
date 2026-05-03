#!/usr/bin/env python3
"""Filtered idevicesyslog viewer for BrokenBlade/DarkSword exploit chain debugging.

Dependencies (auto-detected on first run; install path depends on host OS):

  macOS  - Auto-installs Homebrew + libimobiledevice on first run if either
           is missing. Asks for sudo password when needed.

  Windows - Detects winget; if available, prompts to install
            `imobiledevice-net.imobiledevice-net`. Also reminds the user
            that the Apple Mobile Device Service (driver/pairing layer)
            must be installed separately - either by installing the
            "Apple Devices" app from Microsoft Store or iTunes.

  Linux  - Prints a package-manager hint
           (`apt install libimobiledevice-utils` etc.) and exits if
           tools are missing. No auto-install.

Usage: python3 syslog.py [output_file]
  output_file defaults to brokenblade-logs/syslog_<timestamp>.txt
  Ctrl+C to stop.
"""

import os
import re
import shutil
import signal
import subprocess
import sys
import threading
from pathlib import Path

BREW_BIN_DIRS = ("/opt/homebrew/bin", "/usr/local/bin")
HOMEBREW_INSTALL_URL = "https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh"


def _which(cmd):
    p = shutil.which(cmd)
    if p:
        return p
    for d in BREW_BIN_DIRS:
        full = os.path.join(d, cmd)
        if os.path.isfile(full) and os.access(full, os.X_OK):
            return full
    return None


def _add_brew_to_path():
    parts = os.environ.get("PATH", "").split(":")
    changed = False
    for d in BREW_BIN_DIRS:
        if os.path.isdir(d) and d not in parts:
            parts.insert(0, d)
            changed = True
    if changed:
        os.environ["PATH"] = ":".join(parts)


def _prompt_yes(msg):
    if not sys.stdin.isatty():
        print(f"{msg} (no TTY, refusing to auto-install)")
        return False
    try:
        return input(f"{msg} [y/N] ").strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def _install_homebrew():
    print("[deps] Installing Homebrew (you will be prompted for your sudo password)...")
    rc = subprocess.call([
        "/bin/bash", "-c",
        f'/bin/bash -c "$(curl -fsSL {HOMEBREW_INSTALL_URL})"',
    ])
    return rc == 0


def _brew_install(formula):
    brew = _which("brew")
    if not brew:
        return False
    print(f"[deps] Running: {brew} install {formula}")
    return subprocess.call([brew, "install", formula]) == 0


def _describe_device(udid):
    """Return a dict of selected ideviceinfo fields for udid, or {} on failure."""
    try:
        r = subprocess.run(
            ["ideviceinfo", "-u", udid],
            capture_output=True, text=True, timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {}
    if r.returncode != 0:
        return {}
    info = {}
    wanted = {"DeviceName", "ProductType", "ProductVersion",
              "BuildVersion", "HardwareModel", "CPUArchitecture"}
    for raw in r.stdout.splitlines():
        if ":" not in raw:
            continue
        k, _, v = raw.partition(":")
        k = k.strip()
        if k in wanted:
            info[k] = v.strip()
    return info


def _print_device_banner(udids):
    for i, udid in enumerate(udids):
        info = _describe_device(udid)
        prefix = "[syslog] Detected device" + (f" #{i+1}" if len(udids) > 1 else "") + ":"
        print(prefix)
        if info.get("DeviceName"):
            print(f"[syslog]   Name:   {info['DeviceName']}")
        model_bits = []
        if info.get("ProductType"):
            model_bits.append(info["ProductType"])
        if info.get("HardwareModel"):
            model_bits.append(f"({info['HardwareModel']})")
        if info.get("CPUArchitecture"):
            model_bits.append(f"[{info['CPUArchitecture']}]")
        if model_bits:
            print(f"[syslog]   Model:  {' '.join(model_bits)}")
        if info.get("ProductVersion"):
            ver = info["ProductVersion"]
            if info.get("BuildVersion"):
                ver += f" ({info['BuildVersion']})"
            print(f"[syslog]   iOS:    {ver}")
        print(f"[syslog]   UDID:   {udid}")
    if len(udids) > 1:
        print(f"[syslog] Multiple devices connected; idevicesyslog will follow {udids[0]}.")


WINGET_PACKAGE_ID = "imobiledevice-net.imobiledevice-net"
WINDOWS_INSTALL_GUIDE = (
    "Two pieces are required on Windows:\n"
    "  1. Apple Mobile Device Service (USB pairing/driver layer).\n"
    "       - Install \"Apple Devices\" from the Microsoft Store, OR\n"
    "       - Install iTunes from https://www.apple.com/itunes/.\n"
    "  2. libimobiledevice tools (idevice_id.exe, idevicesyslog.exe).\n"
    "       - winget: winget install --id " + WINGET_PACKAGE_ID + "\n"
    "       - or download a prebuilt zip from\n"
    "           https://github.com/libimobiledevice-win32/imobiledevice-net/releases\n"
    "         and add the extracted folder to your PATH."
)
LINUX_INSTALL_HINT = (
    "Install via your distro's package manager:\n"
    "  Debian/Ubuntu:  sudo apt install libimobiledevice-utils\n"
    "  Fedora/RHEL:    sudo dnf install libimobiledevice-utils\n"
    "  Arch/Manjaro:   sudo pacman -S libimobiledevice\n"
    "  openSUSE:       sudo zypper install libimobiledevice-tools"
)
REQUIRED_TOOLS = ("idevice_id", "idevicesyslog")


def _ensure_darwin():
    _add_brew_to_path()

    if not _which("brew"):
        print("[deps] Homebrew is required to install libimobiledevice.")
        if not _prompt_yes("Install Homebrew now?"):
            print("Cannot continue without Homebrew. See https://brew.sh")
            sys.exit(1)
        if not _install_homebrew():
            print("Homebrew install failed. See https://brew.sh")
            sys.exit(1)
        _add_brew_to_path()
        if not _which("brew"):
            print("Homebrew installed but `brew` is still not on PATH; open a new shell and re-run.")
            sys.exit(1)

    missing = [c for c in REQUIRED_TOOLS if not _which(c)]
    if missing:
        print(f"[deps] Missing: {', '.join(missing)} (provided by libimobiledevice).")
        if not _prompt_yes("Install with `brew install libimobiledevice` now?"):
            print("Cannot continue. Run: brew install libimobiledevice")
            sys.exit(1)
        if not _brew_install("libimobiledevice"):
            print("brew install libimobiledevice failed.")
            sys.exit(1)
        still_missing = [c for c in REQUIRED_TOOLS if not _which(c)]
        if still_missing:
            print(f"Install completed but still cannot find: {', '.join(still_missing)}")
            sys.exit(1)


def _ensure_windows():
    missing = [c for c in REQUIRED_TOOLS if not _which(c)]
    if not missing:
        return

    print(f"[deps] Missing on PATH: {', '.join(missing)} (libimobiledevice tools).")
    print("[deps] Reminder: Apple Mobile Device Service is also required for")
    print("[deps] USB pairing - install \"Apple Devices\" (Microsoft Store) or iTunes.")

    winget = _which("winget")
    if winget:
        if _prompt_yes(f"Try `winget install --id {WINGET_PACKAGE_ID}` now?"):
            rc = subprocess.call([
                winget, "install", "--id", WINGET_PACKAGE_ID,
                "--accept-package-agreements", "--accept-source-agreements",
            ])
            if rc == 0:
                still_missing = [c for c in REQUIRED_TOOLS if not _which(c)]
                if not still_missing:
                    return
                print(f"[deps] winget reported success but {', '.join(still_missing)} not")
                print("[deps] yet on PATH. Open a NEW terminal and re-run this script.")
                sys.exit(1)
            print(f"[deps] winget exited with status {rc}.")
        else:
            print("[deps] Skipping winget install.")
    else:
        print("[deps] winget not detected on PATH.")

    print()
    print("[deps] " + WINDOWS_INSTALL_GUIDE)
    sys.exit(1)


def _ensure_linux_hint():
    missing = [c for c in REQUIRED_TOOLS if not _which(c)]
    if not missing:
        return
    print(f"[deps] Missing on PATH: {', '.join(missing)} (provided by libimobiledevice).")
    print("[deps] " + LINUX_INSTALL_HINT)
    sys.exit(1)


def ensure_dependencies():
    """Dispatch to the platform-appropriate dep installer / hint."""
    if sys.platform == "darwin":
        return _ensure_darwin()
    if sys.platform in ("win32", "cygwin"):
        return _ensure_windows()
    return _ensure_linux_hint()

# --- ANSI colors ---
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[1;36m"
MAGENTA = "\033[1;35m"
RED = "\033[1;31m"
RESET = "\033[0m"

# --- Chain log tags ---
# Bracketed tags come from components that call syslog() directly:
#   sbx1_main  -> [SBX1]       (via print -> syslog)
#   sbcustomizer -> [SBC]      (via Native.callSymbol("syslog"))
#   powercuff  -> [POWERCUFF]  (via Native.callSymbol("syslog"))
#   pe_main embedded payloads  -> [PE], [THREEAPP], [THREEAPP-AUDIT],
#                                 [SAFARI-CLEAN],
#                                 [FILE-DL], [HTTP-UPLOAD], [APP], [ICLOUD],
#                                 [KEYCHAIN], [WIFI], [FILE-DL-EARLY]
#   pe_main kernel phase       -> [PE-*] plus shorthand [+]/[-]/[!]/[i]
#
# NOTE: pe_main.js outer code (CHAIN, INJECTJS, DRIVER-POSTEXPL, TASK, VM,
# MAIN, etc.) uses console.log() which does NOT reliably reach idevicesyslog
# from an injected JSC context. Those tags are included here just in case,
# but the real fix is to switch pe_main to syslog() like sbcustomizer does.
CHAIN_TAGS = re.compile(
    r'\[PE\]|\[PE-DBG\]|\[SBX1\]|\[SBC\]|\[POWERCUFF\]|\[CHAIN-OVL\]|'
    r'\[FILE-DL\]|\[FILE-DL-EARLY\]|\[HTTP-UPLOAD\]|'
    r'\[APP\]|\[ICLOUD\]|\[KEYCHAIN\]|\[WIFI\]|\[THREEAPP\]|\[THREEAPP-AUDIT\]|\[SAFARI-CLEAN\]|'
    r'\[MG\]|\[MPD\]|\[APPLIMIT\]|'
    r'nativeCallBuff|kernel_base|kernel_slide|'
    r'SBX0|SBX1|sbx0:|sbx1:|'
    r'MIG_FILTER_BYPASS |INJECTJS |CHAIN |DRIVER-POSTEXPL |DRIVER-NEWTHREAD |'
    r'DARKSWORD-WIFI-DUMP |INFO |OFFSETS |FILE-UTILS |'
    r'PORTRIGHTINSERTER |REGISTERSSTRUCT |REMOTECALL |'
    r'TASK(?:ROP)? |THREAD |VM |MAIN |EXCEPTION |SANDBOX |'
    r'PAC (?:diagnostics|ptrs|gadget)|UTILS '
)

# --- Interesting patterns (colored) ---
INTERESTING_PATTERNS = [
    (re.compile(r'\[PE\]|\[PE-DBG\]|kernel_base|kernel_slide', re.IGNORECASE), GREEN),
    (re.compile(r'\[SBX1\]|SBX0|SBX1|sbx0:|sbx1:', re.IGNORECASE), MAGENTA),
    (re.compile(r'\[SBC\]|\[POWERCUFF\]|\[CHAIN-OVL\]|\[MG\]|\[APPLIMIT\]|\[THREEAPP\]|\[THREEAPP-AUDIT\]|\[SAFARI-CLEAN\]', re.IGNORECASE), CYAN),
    (re.compile(r'\[FILE-DL\]|\[HTTP-UPLOAD\]|\[APP\]|\[ICLOUD\]|\[KEYCHAIN\]|\[WIFI\]', re.IGNORECASE), CYAN),
    (re.compile(r'MIG_FILTER_BYPASS|INJECTJS|CHAIN |DRIVER-POSTEXPL|DRIVER-NEWTHREAD', re.IGNORECASE), YELLOW),
    (re.compile(r'SIGBUS|SIGSEGV|EXC_BAD|EXC_CRASH|pac_exception|pac.violation', re.IGNORECASE), RED),
    (re.compile(r'threw|SyntaxError|TypeError|ReferenceError', re.IGNORECASE), RED),
]

# --- ReportCrash: only if SpringBoard crashed ---
REPORTCRASH_SB = re.compile(r'ReportCrash.*SpringBoard|SpringBoard.*ReportCrash', re.IGNORECASE)
PE_SHORTHAND_TAGS = re.compile(r'mediaplaybackd(?:\([^)]*\))?\[\d+\].*(?:\[\+\]|\[-\]|\[!\]|\[i\])')

TIMESTAMP_PATTERN = re.compile(r'^[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\.\d+\s+\S+\[\d+\]\s*')
PROCESS_PATTERN = re.compile(r'^[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\.\d+\s+([A-Za-z0-9_.-]+)(?:\([^)]*\))?\[\d+\]')

_seen_messages = set()
_seen_order = []
DEDUP_MAX_SIZE = 50


def is_duplicate(line):
    key = TIMESTAMP_PATTERN.sub('', line)
    if key in _seen_messages:
        return True
    _seen_messages.add(key)
    _seen_order.append(key)
    while len(_seen_order) > DEDUP_MAX_SIZE:
        _seen_messages.discard(_seen_order.pop(0))
    return False


def should_show(line):
    """Only show lines matching chain tags or SpringBoard ReportCrash."""
    if CHAIN_TAGS.search(line):
        return True
    if PE_SHORTHAND_TAGS.search(line):
        return True
    if REPORTCRASH_SB.search(line):
        return True
    return False


def reader(proc, outfile):
    while proc.poll() is None:
        try:
            line = proc.stdout.readline()
            if not line:
                break
            line = line.rstrip('\n')

            if not should_show(line):
                continue

            color = None
            for pattern, pat_color in INTERESTING_PATTERNS:
                if pattern.search(line):
                    color = pat_color
                    break

            if not is_duplicate(line):
                outfile.write(line + "\n")
                outfile.flush()
                if color:
                    print(f"{color}{line}{RESET}", flush=True)
                else:
                    print(line, flush=True)

        except Exception:
            break


def main():
    from datetime import datetime

    ensure_dependencies()

    logdir = Path(__file__).resolve().parent / "brokenblade-logs"
    logdir.mkdir(exist_ok=True)

    if len(sys.argv) > 1:
        outpath = Path(sys.argv[1])
    else:
        stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        outpath = logdir / f"syslog_{stamp}.txt"

    try:
        ids = subprocess.run(
            ["idevice_id", "-l"],
            capture_output=True, text=True, timeout=5,
        )
    except FileNotFoundError:
        print("idevice_id not found. Install with: brew install libimobiledevice")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("idevice_id timed out. Is usbmuxd running? Try replugging the device.")
        sys.exit(1)

    udids = [u.strip() for u in ids.stdout.splitlines() if u.strip()]
    if not udids:
        print("No iPhone detected. Plug in via USB, unlock the device, and tap 'Trust this computer'.")
        sys.exit(1)

    _print_device_banner(udids)

    try:
        proc = subprocess.Popen(
            ["idevicesyslog"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        print("idevicesyslog not found. Install with: brew install libimobiledevice")
        sys.exit(1)

    outfile = open(outpath, "w")
    print(f"[syslog] Monitoring filtered chain logs -> {outpath}")
    print(f"[syslog] PID {proc.pid}, Ctrl+C to stop\n")

    t = threading.Thread(target=reader, args=(proc, outfile), daemon=True)
    t.start()

    def cleanup(*_):
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
        outfile.close()
        print(f"\n[syslog] Stopped. Output saved to {outpath}")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    t.join()
    cleanup()


if __name__ == "__main__":
    main()
