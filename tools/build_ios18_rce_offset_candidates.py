#!/usr/bin/env python3
import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SYMBOL_REPORT = ROOT / "firmware/work/ios18_symbol_offsets_report.json"
MANUAL_REPORT = ROOT / "firmware/work/ios18_manual_offsets_report.json"


TARGETS = {
    "22A3354__iPhone11,8": ROOT / "firmware/extracted/iPhone11_8_18.0_22A3354_Restore/22A3354__iPhone11,8/dyld_shared_cache_arm64e",
    "22B83__iPhone12,1": ROOT / "firmware/extracted/iPhone12_1_18.1_22B83_Restore/22B83__iPhone12,1/dyld_shared_cache_arm64e",
    "22C152__iPhone13,2_3": ROOT / "firmware/extracted/iPhone13_2_iPhone13_3_18.2_22C152_Restore/22C152__iPhone13,2_3/dyld_shared_cache_arm64e",
    "22D63__iPhone14,5": ROOT / "firmware/extracted/iPhone14_5_18.3_22D63_Restore/22D63__iPhone14,5/dyld_shared_cache_arm64e",
}


CONSTANT_OFFSETS = {
    "CAPointer": 0x20,
    "CGContextDelegate": 0x28,
    "GPUConnectionToWebProcess_m_remoteGraphicsContextGLMap": 0xF0,
    "IOSurfaceContextDelegate": 0x120,
    "IOSurfaceDrawable": 0x150,
    "IOSurfaceQueue": 0x48,
    "RemoteRenderingBackendProxy_off": 0x830,
    "UI_m_connection": 0x28,
    "m_backend": 0x70,
    "m_drawingArea": 0x50,
    "m_gpuProcessConnection": 0x158,
    "m_gpuProcessConnection_m_identifier": 0x38,
    "m_imageBuffer": 0x18,
    "m_isRenderingSuspended": 0xE8,
    "m_platformContext": 0x38,
    "m_remoteDisplayLists": 0x70,
    "m_remoteRenderingBackendMap": 0xE8,
    "m_webProcessConnections": 0x80,
    "privateState_off": 0x7E8,
    "rxBufferMtl_off": 0x100,
    "rxMtlBuffer_off": 0x70,
    "vertexAttribVector_off": 0x2548,
}


LINE_RE = re.compile(r"^(0x[0-9a-fA-F]+)")


def run(args):
    return subprocess.run(
        args,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True,
    ).stdout


def fmt(value):
    return f"0x{value:x}n"


def parse_hex_n(value):
    return int(value[:-1], 16)


def image_rows(dsc, image):
    output = run(["ipsw", "dyld", "image", str(dsc), image])
    rows = []
    for line in output.splitlines():
        match = re.match(
            r"\s*(0x[0-9a-fA-F]+)\s+\|\s+(0x[0-9a-fA-F]+)\s+\|\s+(0x[0-9a-fA-F]+)\s+\|\s+([rwx-]+)",
            line,
        )
        if match:
            rows.append(
                {
                    "file_off": int(match.group(1), 16),
                    "file_size": int(match.group(2), 16),
                    "vm_off": int(match.group(3), 16),
                    "perms": match.group(4),
                }
            )
    if not rows:
        raise RuntimeError(f"no image rows parsed for {image}")
    return rows


def cache_offset(dsc, addr):
    output = run(["ipsw", "dyld", "a2o", str(dsc), hex(addr)])
    match = re.search(r"Offset\s+dec=\d+\s+hex=(0x[0-9a-fA-F]+)", output)
    if not match:
        raise RuntimeError(f"could not parse a2o output for {hex(addr)}:\n{output}")
    return int(match.group(1), 16)


def image_base(dsc, image, text_symbol):
    rows = image_rows(dsc, image)
    text_row = next(row for row in rows if row["perms"].startswith("r-x") and row["vm_off"] == 0)
    return text_symbol - (cache_offset(dsc, text_symbol) - text_row["file_off"])


def first_macho_symbol(dsc, image, pattern):
    output = run(["ipsw", "dyld", "symaddr", str(dsc), "--image", image, "--all"])
    for line in output.splitlines():
        if pattern in line and not line.startswith("0x000000000"):
            match = LINE_RE.match(line)
            if match:
                return int(match.group(1), 16)
    raise RuntimeError(f"could not find {pattern} in {image}")


def qword_at(dsc, addr):
    output = run(["ipsw", "dyld", "dump", str(dsc), hex(addr), "--count", "1", "--addr"])
    match = LINE_RE.search(output)
    if not match:
        raise RuntimeError(f"could not read qword at {hex(addr)}:\n{output}")
    return int(match.group(1), 16)


def runtime_state_vtable(dsc, symbol):
    output = run(["ipsw", "dyld", "dump", str(dsc), hex(symbol), "--count", "8", "--addr"])
    for idx, line in enumerate(output.splitlines()):
        match = LINE_RE.match(line)
        if not match:
            continue
        value = int(match.group(1), 16)
        if idx >= 2 and value:
            return symbol + idx * 8, value
    raise RuntimeError(f"could not derive RuntimeState vtable from {hex(symbol)}")


def runloop_holder_tid(dsc, func):
    output = run(["ipsw", "dyld", "disass", str(dsc), "--vaddr", hex(func), "--quiet", "--count", "12"])
    adrp = None
    for line in output.splitlines():
        match = re.search(r"adrp\s+x0,\s*(0x[0-9a-fA-F]+)", line)
        if match:
            adrp = int(match.group(1), 16)
            continue
        match = re.search(r"add\s+x0,\s*x0,\s*#(0x[0-9a-fA-F]+|\d+)", line)
        if adrp is not None and match:
            return adrp + int(match.group(1), 0)
    raise RuntimeError(f"could not derive runLoopHolder tid from {hex(func)}")


def libdyld_gapis(dsc):
    image = "/usr/lib/system/libdyld.dylib"
    dlopen = first_macho_symbol(dsc, image, "_dlopen")
    base = image_base(dsc, image, dlopen)
    rows = image_rows(dsc, image)
    candidates = [row for row in rows if row["perms"].startswith("rw") and row["file_size"] <= 0x50]
    if not candidates:
        raise RuntimeError("could not find libdyld gAPIs region")
    return base + candidates[-1]["vm_off"]


def desktopservices_bss(dsc):
    image = "/System/Library/PrivateFrameworks/DesktopServicesPriv.framework/DesktopServicesPriv"
    first_text = first_macho_symbol(dsc, image, "DesktopServicesPriv")
    base = image_base(dsc, image, first_text)
    rows = image_rows(dsc, image)
    bss_row = next(row for row in rows if 0x1400 <= row["file_size"] <= 0x1500)
    return base + bss_row["vm_off"] + 0xA98


def avfaudio_cfstring(dsc):
    image = "/System/Library/Frameworks/AVFAudio.framework/AVFAudio"
    text_sym = first_macho_symbol(dsc, image, "AVLoadSpeechSynthesisImplementationv_block_invoke")
    base = image_base(dsc, image, text_sym)
    rows = image_rows(dsc, image)
    cf_row = next(row for row in rows if 0xD00 <= row["file_size"] <= 0xE00)
    return base + cf_row["vm_off"] + 0xCDC0


def jsc_private_globals(dsc, symbols):
    rows = image_rows(dsc, "/System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore")
    base = parse_hex_n(symbols["jsc_base"])
    data_row = next(row for row in rows if row["file_size"] > 0x20000 and row["file_size"] < 0x30000)
    return {
        "JavaScriptCore__jitAllowList": base + data_row["vm_off"] + 0x2A4A0,
        "JavaScriptCore__jitAllowList_once": base + data_row["vm_off"] + 0x2A2B8,
    }


def main():
    symbol_report = json.loads(SYMBOL_REPORT.read_text())
    manual_report = json.loads(MANUAL_REPORT.read_text())
    out = {}

    for tag, dsc in TARGETS.items():
        symbols = {key: parse_hex_n(value) for key, value in symbol_report[tag]["symbols"].items()}
        manual = {key: parse_hex_n(value) for key, value in manual_report[tag]["manual_offsets"].items()}
        values = {}
        values.update(CONSTANT_OFFSETS)
        values.update(symbols)
        values.update(manual)

        values["AVFAudio__cfstr_SystemLibraryTextToSpeech"] = avfaudio_cfstring(dsc)
        values["DesktopServicesPriv_bss"] = desktopservices_bss(dsc)
        values.update(jsc_private_globals(dsc, symbol_report[tag]["symbols"]))
        values["RemoteGraphicsContextGLWorkQueue"] = values["WebProcess_singleton"] - 0x11A8
        values["WebCore__DedicatedWorkerGlobalScope_vtable"] = first_macho_symbol(
            dsc,
            "/System/Library/PrivateFrameworks/WebCore.framework/WebCore",
            "__ZTVN7WebCore26DedicatedWorkerGlobalScopeE",
        ) + 0x10
        runtime_vtable_sym = first_macho_symbol(dsc, "/usr/lib/dyld", "__ZTVN5dyld412RuntimeStateE")
        values["dyld__RuntimeState_vtable"], values["dyld__RuntimeState_emptySlot"] = runtime_state_vtable(dsc, runtime_vtable_sym)
        dlopen_lambda = first_macho_symbol(dsc, "/usr/lib/dyld", "__ZZN5dyld44APIs11dlopen_fromEPKciPvENK3$_0clEv")
        values["dyld__dlopen_from_lambda_ret"] = dlopen_lambda + 0x740
        values["libdyld__gAPIs"] = libdyld_gapis(dsc)
        values["mach_task_self_ptr"] = first_macho_symbol(dsc, "/usr/lib/system/libsystem_kernel.dylib", "_mach_task_self_")
        values["mainRunLoop"] = first_macho_symbol(
            dsc,
            "/System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore",
            "__ZN3WTFL13s_mainRunLoopE",
        )
        runloop_func = first_macho_symbol(
            dsc,
            "/System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore",
            "runLoopHolderEvE3$_0",
        )
        values["runLoopHolder_tid"] = runloop_holder_tid(dsc, runloop_func)

        out[tag] = {
            "ios": symbol_report[tag]["ios"],
            "device_key": symbol_report[tag]["device_key"],
            "offsets": {key: fmt(value) for key, value in sorted(values.items())},
            "caveat": "candidate offsets derived from symbol, byte-pattern, string, and stable-layout deltas; device validation still required before removing runtime guard",
        }

    print(json.dumps(out, indent=2, sort_keys=True))


if __name__ == "__main__":
    sys.exit(main())
