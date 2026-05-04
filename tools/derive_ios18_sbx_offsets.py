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


SBX0_18_4_MESSAGE_IDS = {
    "GPUConnectionToWebProcess_CreateGraphicsContextGL": 0x29,
    "GPUConnectionToWebProcess_CreateRenderingBackend": 0x2b,
    "InitializeConnection": 0xbd9,
    "ProcessOutOfStreamMessage": 0xbdb,
    "RemoteDisplayListRecorder_DrawGlyphs": 0x3ca,
    "RemoteDisplayListRecorder_FillRect": 0x3df,
    "RemoteDisplayListRecorder_SetCTM": 0x3ea,
    "RemoteDisplayListRecorder_StrokeRect": 0x3fe,
    "RemoteGraphicsContextGLProxy_WasCreated": 0x408,
    "RemoteGraphicsContextGL_AttachShader": 0x40c,
    "RemoteGraphicsContextGL_BindBuffer": 0x411,
    "RemoteGraphicsContextGL_BindTexture": 0x417,
    "RemoteGraphicsContextGL_BufferData0": 0x424,
    "RemoteGraphicsContextGL_BufferData1": 0x425,
    "RemoteGraphicsContextGL_BufferSubData": 0x426,
    "RemoteGraphicsContextGL_CompileShader": 0x432,
    "RemoteGraphicsContextGL_CreateBuffer": 0x43f,
    "RemoteGraphicsContextGL_CreateProgram": 0x441,
    "RemoteGraphicsContextGL_CreateShader": 0x446,
    "RemoteGraphicsContextGL_CreateTexture": 0x447,
    "RemoteGraphicsContextGL_Finish": 0x46f,
    "RemoteGraphicsContextGL_Flush": 0x470,
    "RemoteGraphicsContextGL_GetBufferSubDataInline": 0xf0d,
    "RemoteGraphicsContextGL_GetShaderSource": 0xf25,
    "RemoteGraphicsContextGL_LinkProgram": 0x47a,
    "RemoteGraphicsContextGL_PixelStorei": 0x482,
    "RemoteGraphicsContextGL_Reshape": 0x48d,
    "RemoteGraphicsContextGL_ShaderSource": 0x496,
    "RemoteGraphicsContextGL_TexImage2D1": 0x49f,
    "RemoteGraphicsContextGL_UseProgram": 0x4cd,
    "RemoteGraphicsContextGL_VertexAttrib4f": 0x4d5,
    "RemoteImageBufferProxy_DidCreateBackend": 0x4e0,
    "RemoteImageBuffer_PutPixelBuffer": 0x4e6,
    "RemoteRenderingBackendProxy_DidInitialize": 0x5a4,
    "RemoteRenderingBackend_CacheFont": 0x5a8,
    "RemoteRenderingBackend_CreateImageBuffer": 0x5ac,
    "RemoteRenderingBackend_ReleaseImageBuffer": 0x5bc,
    "RemoteRenderingBackend_ReleaseRenderingResource": 0x5c1,
    "SyncMessageReply": 0xbdd,
    "WebProcessProxy_GPUProcessConnectionDidBecomeUnresponsive": 0xaca,
}


SBX1_SEARCHES = {
    "malloc_restore_0_gadget": {
        "image": "/System/Library/PrivateFrameworks/AppSupport.framework/AppSupport",
        "pattern": "02 18 40 f9 62 00 00 b4 01 1c 40 f9 5f 08 1f d6",
    },
    "malloc_restore_1_gadget": {
        "image": "/System/Library/PrivateFrameworks/PersonalizationPortraitInternals.framework/PersonalizationPortraitInternals",
        "pattern": "00 10 40 f9 21 04 40 f9 e3 03 00 aa 64 0c 41 f8 02 00 80 d2 83 08 1f d7",
    },
    "malloc_restore_2_gadget": {
        "image": "/usr/lib/dyld",
        "pattern": "00 10 40 f9 e3 03 00 aa 64 0c 41 f8",
        "select": 0,
    },
    "malloc_restore_3_gadget": {
        "image": "/System/Library/PrivateFrameworks/AudioToolboxCore.framework/AudioToolboxCore",
        "pattern": "08 14 40 f9 01 01 00 f9 00 10 40 f9 e1 03 00 aa 22 0c 41 f8 41 08 1f d7",
    },
    "self_loop": {
        "image": "/System/Library/PrivateFrameworks/AudioToolboxCore.framework/AudioToolboxCore",
        "pattern": "09 00 40 f9 3f 09 3f d6 08 00 00 b9",
    },
    "tcall_DSSG": {
        "image": "/System/Library/PrivateFrameworks/WeatherDaemon.framework/WeatherDaemon",
        "pattern": "5f 03 00 91 c0 03 5f d6",
        "select": 0,
    },
    "tcall_DG": {
        "image": "/System/Library/PrivateFrameworks/MusicKitInternal.framework/MusicKitInternal",
        "pattern": "b1 e8 e1 f2 d1 0a 3f d7",
        "adjust": -4,
        "select": 0,
    },
    "load_x1x3x8": {
        "image": "/usr/lib/libHSFilerDynamic.dylib",
        "pattern": "01 8c 42 a9 08 10 40 f9 e4 03 08 aa 85 0c 41 f8 e0 03 08 aa 02 00 80 52 a4 08 1f d7",
        "select": 0,
    },
    "fcall_14_args_write_x8": {
        "image": "/System/Library/PrivateFrameworks/FitnessCanvasUI.framework/FitnessCanvasUI",
        "pattern": "7f 23 03 d5 ff 43 01 d1 f4 4f 03 a9 fd 7b 04 a9 fd 03 01 91 e9 03 03 aa f3 03 08 aa 20 20 41 a9",
    },
    "_4_fcalls": {
        "image": "/System/Library/PrivateFrameworks/SiriSuggestionsKit.framework/SiriSuggestionsKit",
        "pattern": "7f 23 03 d5 f6 57 bd a9 f4 4f 01 a9 fd 7b 02 a9 fd 83 00 91 f3 03 06 aa f4 03 05 aa f5 03 04 aa",
        "select": 0,
    },
    "jsvm_isNAN_fcall_gadget": {
        "image": "/System/Library/Frameworks/NetworkExtension.framework/NetworkExtension",
        "pattern": "20 18 40 f9 80 00 00 b4 08 0c 40 f9 02 21 40 f9 5f 08 1f d6",
    },
    "store_x0_x0": {
        "image": "/System/Library/Frameworks/MediaToolbox.framework/MediaToolbox",
        "pattern": "00 04 00 f9 c0 03 5f d6",
    },
    "str_x1_x2": {
        "image": "/System/Library/Frameworks/SceneKit.framework/SceneKit",
        "pattern": "41 00 00 f9 c0 03 5f d6",
    },
    "add_x22_0x90": {
        "image": "/System/Library/PrivateFrameworks/ActionKit.framework/ActionKit",
        "pattern": "d6 42 02 91 c0 03 5f d6",
    },
}


SBX1_SYMBOLS = {
    "_CFObjectCopyProperty": ("__CFObjectCopyProperty", 0),
    "dyld_signPointer_gadget": ("__ZN6mach_o25ChainedFixupPointerOnDisk6Arm64e11signPointerEyPvbth", 0),
    "jsvm_isNAN_fcall_gadget2": ("__ZN4mlir19CallableOpInterface14getResultTypesEv", 4),
    "transformSurface_gadget": ("_transformSurface", 0),
    "xpac_gadget": ("_ptr_auth_strip", 0),
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
    out = []
    for line in output.splitlines():
        match = ADDR_RE.match(line)
        if match:
            out.append(int(match.group(1), 16))
    return out


def macho_search(dsc, image, pattern, select=None, adjust=0):
    output = run(["ipsw", "dyld", "macho", str(dsc), image, "--search", pattern, "--no-color"])
    addrs = parse_addrs(output)
    if not addrs:
        raise RuntimeError(f"no match for {pattern} in {image}")
    if select is None:
        if len(addrs) != 1:
            raise RuntimeError(f"expected one match for {pattern} in {image}, got {[hex(a) for a in addrs]}")
        select = 0
    return addrs[select] + adjust


def all_macho_search(dsc, pattern, preferred_image=None):
    output = run(["ipsw", "dyld", "macho", str(dsc), "--all", "--search", pattern, "--no-color"])
    hits = []
    for line in output.splitlines():
        if not line.startswith("0x"):
            continue
        addr_s, image = line.split(None, 1)
        if preferred_image is None or preferred_image in image:
            hits.append(int(addr_s, 16))
    if not hits:
        raise RuntimeError(f"no --all match for {pattern}")
    return hits[0]


def symaddr(dsc, symbol):
    output = run(["ipsw", "dyld", "symaddr", str(dsc), symbol, "--no-color"])
    addrs = parse_addrs(output)
    if not addrs:
        raise RuntimeError(f"no symbol {symbol}")
    return addrs[0]


def main():
    symbol_report = json.loads(SYMBOL_REPORT.read_text())
    manual_report = json.loads(MANUAL_REPORT.read_text())
    out = {}

    for tag, dsc in TARGETS.items():
        if not dsc.exists():
            raise SystemExit(f"missing DSC: {dsc}")
        symbols = symbol_report[tag]["symbols"]
        manual = manual_report[tag]["manual_offsets"]
        sbx1 = {}

        for key, cfg in SBX1_SEARCHES.items():
            sbx1[key] = macho_search(
                dsc,
                cfg["image"],
                cfg["pattern"],
                select=cfg.get("select"),
                adjust=cfg.get("adjust", 0),
            )

        for key, (symbol, adjust) in SBX1_SYMBOLS.items():
            sbx1[key] = symaddr(dsc, symbol) + adjust

        sbx1["tcall_CRLG"] = int(manual["gadget_control_1_ios184"][:-1], 16)
        sbx1["tcall_X0LG"] = int(manual["gadget_control_3_ios184"][:-1], 16)
        sbx1["tcall_RLG"] = int(manual["gadget_set_all_registers_ios184"][:-1], 16) + 0xC
        sbx1["tcall_CSSG"] = int(manual["gadget_control_2_ios184"][:-1], 16) + 0x14

        sbx1["mov_x0_x22"] = all_macho_search(
            dsc,
            "e0 03 16 aa e1 03 13 aa c0 03 5f d6",
            preferred_image="/System/Library/PrivateFrameworks/BiomeStreams.framework/BiomeStreams",
        )

        out[tag] = {
            "ios": symbol_report[tag]["ios"],
            "device_key": symbol_report[tag]["device_key"],
            "sbx0_offsets": {key: hex(value) for key, value in SBX0_18_4_MESSAGE_IDS.items()},
            "sbx1_offsets": {key: fmt(value) for key, value in sorted(sbx1.items())},
            "notes": {
                "sbx0_offsets": "MessageName IDs match the 18.4 table shape and predate the 18.5 +1 WebKit enum shift seen in 22F76+.",
                "sbx1_shared_rce_gadgets": "tcall_CRLG/tcall_X0LG/tcall_RLG/tcall_CSSG are derived from the already-validated RCE JOP anchors.",
                "mov_x0_x22": "Uses the first exact mov x0,x22; mov x1,x19; ret gadget in BiomeStreams for early builds; the original MediaToolbox outlined gadget is not present on these samples.",
            },
        }

    print(json.dumps(out, indent=2, sort_keys=True))


if __name__ == "__main__":
    sys.exit(main())
