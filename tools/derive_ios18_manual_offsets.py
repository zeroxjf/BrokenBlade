#!/usr/bin/env python3
import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "firmware/work/ios18_symbol_offsets_report.json"


TARGETS = {
    "22A3354__iPhone11,8": ROOT / "firmware/extracted/iPhone11_8_18.0_22A3354_Restore/22A3354__iPhone11,8/dyld_shared_cache_arm64e",
    "22B83__iPhone12,1": ROOT / "firmware/extracted/iPhone12_1_18.1_22B83_Restore/22B83__iPhone12,1/dyld_shared_cache_arm64e",
    "22C152__iPhone13,2_3": ROOT / "firmware/extracted/iPhone13_2_iPhone13_3_18.2_22C152_Restore/22C152__iPhone13,2_3/dyld_shared_cache_arm64e",
    "22D63__iPhone14,5": ROOT / "firmware/extracted/iPhone14_5_18.3_22D63_Restore/22D63__iPhone14,5/dyld_shared_cache_arm64e",
}


SEARCHES = {
    "gadget_control_1_ios184": {
        "image": "/System/Library/Extensions/AppleHDQGasGaugeControl.kext/PlugIns/AppleHDQGasGaugeHID.plugin/AppleHDQGasGaugeHID",
        "pattern": "fd 7b 49 a9 f4 4f 48 a9 f6 57 47 a9 f8 5f 46 a9 fa 67 45 a9 fc 6f 44 a9 e9 23 43 6d eb 2b 42 6d ed 33 41 6d ef 3b ca 6c ff 0f 5f d6",
    },
    "gadget_control_3_ios184": {
        "image": "/System/Library/Frameworks/Charts.framework/Charts",
        "pattern": "80 06 42 a9 fd 7b c1 a8 ff 0f 5f d6",
    },
    "gadget_loop_1_ios184": {
        "image": "/System/Library/PrivateFrameworks/UIKitCore.framework/UIKitCore",
        "pattern": "60 12 00 f9 68 02 40 f9 1f 09 3f d6 68 06 40 f9",
    },
    "gadget_loop_2_ios184": {
        "image": "/usr/lib/system/libcorecrypto.dylib",
        "pattern": "60 06 00 f9 88 0a 40 f9 1f 09 3f d6",
    },
    "gadget_loop_3_ios184": {
        "image": "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics",
        "pattern": "08 04 40 f9 1f 09 3f d6 e1 03 00 aa 20 00 80 52",
    },
    "gadget_set_all_registers_ios184": {
        "image": "/System/Library/Frameworks/Accelerate.framework/Frameworks/vecLib.framework/libvDSP.dylib",
        "pattern": "00 02 00 f9 f0 03 00 aa e7 1b c1 6c e5 13 c1 6c e3 0b c1 6c e1 03 c1 6c e7 1b c1 a8",
        "adjust": -8,
    },
    "libGPUCompilerImplLazy__invoker": {
        "image": "/System/Library/PrivateFrameworks/GPUCompiler.framework/Libraries/libGPUCompilerImplLazy.dylib",
        "pattern": "08 00 40 a9 1f 09 3f d6 00 00 80 52",
        "adjust": -12,
    },
}


STRINGS = {
    "HOMEUI_cstring": {
        "needle": "/System/Library/AccessibilityBundles/HomeUI.axbundle/HomeUI",
        "image": "CoreFoundation",
    },
    "PerfPowerServicesReader_cstring": {
        "needle": "/System/Library/PrivateFrameworks/PerfPowerServicesReader.framework/PerfPowerServicesReader",
        "image": "PerfPowerServicesReader",
    },
    "libARI_cstring": {
        "needle": "/usr/lib/libARI.dylib",
        "image": "libARI.dylib",
    },
    "libGPUCompilerImplLazy_cstring": {
        "needle": "/System/Library/PrivateFrameworks/GPUCompiler.framework/Libraries/libGPUCompilerImplLazy.dylib",
        "image": "libGPUCompilerImplLazy.dylib",
    },
}


ADDR_RE = re.compile(r"^(0x[0-9a-fA-F]+)")


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


def parse_addrs(output):
    addrs = []
    for line in output.splitlines():
        match = ADDR_RE.match(line)
        if match:
            addrs.append(int(match.group(1), 16))
    return addrs


def macho_search(dsc, image, pattern):
    output = run(["ipsw", "dyld", "macho", str(dsc), image, "--search", pattern])
    return parse_addrs(output)


def string_addr(dsc, needle, image):
    output = run(["ipsw", "dyld", "str", str(dsc), needle])
    for line in output.splitlines():
        if f'image={image}' not in line:
            continue
        match = ADDR_RE.match(line)
        if match:
            return int(match.group(1), 16)
    raise RuntimeError(f"could not find {needle!r} in image={image} for {dsc}")


def main():
    symbol_report = json.loads(REPORT.read_text())
    out = {}
    for tag, dsc in TARGETS.items():
        if not dsc.exists():
            raise SystemExit(f"missing DSC: {dsc}")
        symbols = symbol_report[tag]["symbols"]
        values = {}

        for key, cfg in SEARCHES.items():
            addrs = macho_search(dsc, cfg["image"], cfg["pattern"])
            if not addrs:
                raise RuntimeError(f"{key}: no matches in {dsc}")
            addr = addrs[0] + cfg.get("adjust", 0)
            values[key] = addr

        values["gadget_control_2_ios184"] = int(symbols["libdyld__dlopen"][:-1], 16) - 0x1B90

        for key, cfg in STRINGS.items():
            values[key] = string_addr(dsc, cfg["needle"], cfg["image"])

        out[tag] = {
            "ios": symbol_report[tag]["ios"],
            "device_key": symbol_report[tag]["device_key"],
            "manual_offsets": {key: fmt(value) for key, value in sorted(values.items())},
            "notes": {
                "gadget_control_2_ios184": "derived as libdyld__dlopen - 0x1b90, matching bundled 18.5/18.6 tables",
                "gadget_set_all_registers_ios184": "byte pattern matches the str-x0 resolver body; gadget starts 8 bytes before the match",
                "libGPUCompilerImplLazy__invoker": "byte pattern matches ldp x8,x0; blraaz x8; mov w0,#0 body; function starts 12 bytes before the match",
            },
        }

    print(json.dumps(out, indent=2, sort_keys=True))


if __name__ == "__main__":
    sys.exit(main())
