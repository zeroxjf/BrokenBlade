#!/usr/bin/env python3
import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIRMWARE = ROOT / "firmware"
WORK = FIRMWARE / "work"
JSC_IMAGE = "/System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore"


TARGETS = {
    "22A3354__iPhone11,8": {
        "ios": "18.0",
        "device_key": "iPhone11,8_22A3354",
        "dsc": FIRMWARE / "extracted/iPhone11_8_18.0_22A3354_Restore/22A3354__iPhone11,8/dyld_shared_cache_arm64e",
    },
    "22B83__iPhone12,1": {
        "ios": "18.1",
        "device_key": "iPhone12,1_22B83",
        "dsc": FIRMWARE / "extracted/iPhone12_1_18.1_22B83_Restore/22B83__iPhone12,1/dyld_shared_cache_arm64e",
    },
    "22C152__iPhone13,2_3": {
        "ios": "18.2",
        "device_key": "iPhone13,2_3_22C152",
        "dsc": FIRMWARE / "extracted/iPhone13_2_iPhone13_3_18.2_22C152_Restore/22C152__iPhone13,2_3/dyld_shared_cache_arm64e",
    },
    "22D63__iPhone14,5": {
        "ios": "18.3",
        "device_key": "iPhone14,5_22D63",
        "dsc": FIRMWARE / "extracted/iPhone14_5_18.3_22D63_Restore/22D63__iPhone14,5/dyld_shared_cache_arm64e",
    },
}


SYMBOL_PATTERNS = {
    "__pthread_head": r"___pthread_head\s+libsystem_pthread\.dylib$",
    "AVFAudio__AVLoadSpeechSynthesisImplementation_onceToken": r"__ZZ36_AVLoadSpeechSynthesisImplementationvE9onceToken\s+AVFAudio$",
    "AVFAudio__OBJC_CLASS__AVSpeechSynthesisMarker": r"_OBJC_CLASS_\$_AVSpeechSynthesisMarker(?:\s|$)",
    "AVFAudio__OBJC_CLASS__AVSpeechSynthesisProviderRequest": r"_OBJC_CLASS_\$_AVSpeechSynthesisProviderRequest(?:\s|$)",
    "AVFAudio__OBJC_CLASS__AVSpeechSynthesisVoice": r"_OBJC_CLASS_\$_AVSpeechSynthesisVoice(?:\s|$)",
    "AVFAudio__OBJC_CLASS__AVSpeechUtterance": r"_OBJC_CLASS_\$_AVSpeechUtterance(?:\s|$)",
    "AXCoreUtilities__DefaultLoader": r"_defaultLoader\._DefaultLoader\s+AXCoreUtilities$",
    "Foundation__NSBundleTables_bundleTables_value": r"__32\+\[__NSBundleTables bundleTables\]_block_invoke\s+Foundation$",
    "GetCurrentThreadTLSIndex_CurrentThreadIndex": r"__ZZN3eglL24GetCurrentThreadTLSIndexEvE18CurrentThreadIndex\s+libANGLE-shared\.dylib$",
    "JavaScriptCore__globalFuncParseFloat": r"__ZN3JSC20globalFuncParseFloatEPNS_14JSGlobalObjectEPNS_9CallFrameE\s+JavaScriptCore$",
    "ImageIO__IIOLoadCMPhotoSymbols": r"__ZL21IIOLoadCMPhotoSymbolsv\s+ImageIO$",
    "MediaAccessibility__MACaptionAppearanceGetDisplayType": r"_MACaptionAppearanceGetDisplayType(?:\s|$)",
    "WebProcess_singleton": r"__ZZN6WebKit10WebProcess9singletonEvE7process\s+WebKit$",
    "WebProcess_ensureGPUProcessConnection": r"__ZN6WebKit10WebProcess26ensureGPUProcessConnectionEv\s+WebKit$",
    "WebProcess_gpuProcessConnectionClosed": r"__ZN6WebKit10WebProcess26gpuProcessConnectionClosedEv\s+WebKit$",
    "GPUProcess_singleton": r"__ZZN6WebKit10GPUProcess9singletonEvE10gpuProcess\s+WebKit$",
    "GPUProcess_singleton_func": r"__ZN6WebKit10GPUProcess9singletonEv\s+WebKit$",
    "dyld__signPointer": r"(?:__ZN5dyld4L11signPointerEyPvbt11ptrauth_key|__ZN6mach_o25ChainedFixupPointerOnDisk6Arm64e11signPointerEyPvbth)\s+dyld$",
    "libdyld__dlopen": r"__ZN5dyld44APIs6dlopenEPKci\s+dyld$",
    "libdyld__dlsym": r"__ZN5dyld44APIs5dlsymEPvPKc\s+dyld$",
    "WebCore__ZZN7WebCoreL29allScriptExecutionContextsMapEvE8contexts": r"__ZZN7WebCoreL29allScriptExecutionContextsMapEvE8contexts\s+WebCore$",
    "CFNetwork__gConstantCFStringValueTable": r"_gConstantCFStringValueTable\s+CFNetwork$",
    "CMPhoto__CMPhotoCompressionCreateContainerFromImageExt": r"_CMPhotoCompressionCreateContainerFromImageExt(?:\s|$)",
    "CMPhoto__CMPhotoCompressionCreateDataContainerFromImage": r"_CMPhotoCompressionCreateDataContainerFromImage(?:\s|$)",
    "CMPhoto__CMPhotoCompressionSessionAddAuxiliaryImage": r"_CMPhotoCompressionSessionAddAuxiliaryImage(?:\s|$)",
    "CMPhoto__CMPhotoCompressionSessionAddAuxiliaryImageFromDictionaryRepresentation": r"_CMPhotoCompressionSessionAddAuxiliaryImageFromDictionaryRepresentation(?:\s|$)",
    "CMPhoto__CMPhotoCompressionSessionAddCustomMetadata": r"_CMPhotoCompressionSessionAddCustomMetadata(?:\s|$)",
    "CMPhoto__CMPhotoCompressionSessionAddExif": r"_CMPhotoCompressionSessionAddExif(?:\s|$)",
    "CMPhoto__kCMPhotoTranscodeOption_Strips": r"_kCMPhotoTranscodeOption_Strips(?:\s|$)",
    "ImageIO__gFunc_CMPhotoCompressionCreateContainerFromImageExt": r"_gFunc_CMPhotoCompressionCreateContainerFromImageExt\s+ImageIO$",
    "ImageIO__gFunc_CMPhotoCompressionCreateDataContainerFromImage": r"_gFunc_CMPhotoCompressionCreateDataContainerFromImage\s+ImageIO$",
    "ImageIO__gFunc_CMPhotoCompressionSessionAddAuxiliaryImage": r"_gFunc_CMPhotoCompressionSessionAddAuxiliaryImage\s+ImageIO$",
    "ImageIO__gFunc_CMPhotoCompressionSessionAddAuxiliaryImageFromDictionaryRepresentation": r"_gFunc_CMPhotoCompressionSessionAddAuxiliaryImageFromDictionaryRepresentation\s+ImageIO$",
    "ImageIO__gFunc_CMPhotoCompressionSessionAddCustomMetadata": r"_gFunc_CMPhotoCompressionSessionAddCustomMetadata\s+ImageIO$",
    "ImageIO__gFunc_CMPhotoCompressionSessionAddExif": r"_gFunc_CMPhotoCompressionSessionAddExif\s+ImageIO$",
    "ImageIO__gImageIOLogProc": r"gImageIOLogProc\s+ImageIO$",
    "Security__gSecurityd": r"_gSecurityd(?:\s|$)",
    "Security__SecKeychainBackupSyncable_block_invoke": r"____SecKeychainBackupSyncable_block_invoke\s+Security$",
    "Security__SecOTRSessionProcessPacketRemote_block_invoke": r"___SecOTRSessionProcessPacketRemote_block_invoke\s+Security$",
    "TextToSpeech__OBJC_CLASS__TtC12TextToSpeech27TTSMagicFirstPartyAudioUnit": r"_OBJC_CLASS_\$__TtC12TextToSpeech27TTSMagicFirstPartyAudioUnit(?:\s|$)",
    "WebCore__PAL_getPKContactClass": r"__ZN3PAL17getPKContactClassE(?:\s|$)",
    "WebCore__TelephoneNumberDetector_phoneNumbersScanner_value": r"TelephoneNumberDetectorL19phoneNumbersScannerEvE",
    "WebCore__initPKContact_once": r"__ZGVZN3PALL13initPKContactEvE",
    "WebCore__initPKContact_value": r"__ZZN3PALL13initPKContactEvE",
    "WebCore__initPKContact_func": r"__ZN3PALL13initPKContactEv\s+WebCore$",
    "WebCore__softLinkDDDFACacheCreateFromFramework": r"softLinkDDDFACacheCreateFromFramework",
    "WebCore__softLinkDDDFAScannerFirstResultInUnicharArray": r"softLinkDDDFAScannerFirstResultInUnicharArray",
    "WebCore__softLinkMediaAccessibilityMACaptionAppearanceGetDisplayType": r"softLinkMediaAccessibilityMACaptionAppearanceGetDisplayType",
    "WebCore__softLinkOTSVGOTSVGTableRelease": r"softLinkOTSVGOTSVGTableRelease",
    "emptyString": r"__ZN3WTF15emptyStringDataE(?:\s|$)",
    "free_slabs": r"__ZN2CA2CG5Queue11_free_slabsE\s+QuartzCore$",
    "libsystem_c__atexit_mutex": r"_atexit_mutex\s+libsystem_c\.dylib$",
    "libsystem_kernel__thread_suspend": r"_thread_suspend(?:\s|$)",
}

OBJC_CLASS_SYMBOLS = {
    "AVFAudio__OBJC_CLASS__AVSpeechSynthesisMarker": "AVSpeechSynthesisMarker",
    "AVFAudio__OBJC_CLASS__AVSpeechSynthesisProviderRequest": "AVSpeechSynthesisProviderRequest",
    "AVFAudio__OBJC_CLASS__AVSpeechSynthesisVoice": "AVSpeechSynthesisVoice",
    "AVFAudio__OBJC_CLASS__AVSpeechUtterance": "AVSpeechUtterance",
}


LINE_RE = re.compile(r"^(0x[0-9a-fA-F]+):")
DUMP_LINE_RE = re.compile(r"^(0x[0-9a-fA-F]+)$")


def read_symbols(path):
    symbols = {}
    compiled = {key: re.compile(pattern) for key, pattern in SYMBOL_PATTERNS.items()}
    remaining = set(compiled)
    with path.open("r", errors="replace") as handle:
        for line in handle:
            if not remaining:
                break
            match = LINE_RE.match(line)
            if not match:
                continue
            if match.group(1) == "0x000000000":
                continue
            for key in list(remaining):
                if compiled[key].search(line):
                    symbols[key] = int(match.group(1), 16)
                    remaining.remove(key)
                    break
    return symbols, sorted(remaining)


def cache_offset(dsc, addr):
    proc = subprocess.run(
        ["ipsw", "dyld", "a2o", str(dsc), hex(addr)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True,
    )
    match = re.search(r"Offset\s+dec=\d+\s+hex=(0x[0-9a-fA-F]+)", proc.stdout)
    if not match:
        raise RuntimeError(f"could not parse a2o output for {hex(addr)}:\n{proc.stdout}")
    return int(match.group(1), 16)


def image_rows(dsc, image):
    proc = subprocess.run(
        ["ipsw", "dyld", "image", str(dsc), image],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True,
    )
    rows = []
    for line in proc.stdout.splitlines():
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
        raise RuntimeError(f"no image rows parsed for {image} in {dsc}")
    return rows


def image_base_for_symbol(dsc, image, addr):
    file_off = cache_offset(dsc, addr)
    for row in image_rows(dsc, image):
        row_start = row["file_off"]
        row_end = row_start + row["file_size"]
        if row_start <= file_off < row_end:
            vm_off = row["vm_off"] + file_off - row_start
            return addr - vm_off
    raise RuntimeError(f"could not map file offset {hex(file_off)} into {image} rows for {hex(addr)}")


def pthread_image_layout(tag):
    path = WORK / f"{tag}_libsystem_pthread_image.txt"
    if not path.exists():
        raise RuntimeError(f"missing pthread image report: {path}")
    text_file_off = None
    linkedit_vm_off = None
    rows = []
    for line in path.read_text(errors="replace").splitlines():
        match = re.match(r"\s*(0x[0-9a-fA-F]+)\s+\|\s+(0x[0-9a-fA-F]+)\s+\|\s+(0x[0-9a-fA-F]+)\s+\|\s+([rwx-]+)", line)
        if match:
            rows.append((int(match.group(1), 16), int(match.group(3), 16), match.group(4)))
    for file_off, vm_off, perms in rows:
        if perms.startswith("r-x") and vm_off == 0:
            text_file_off = file_off
            break
    for file_off, vm_off, perms in reversed(rows):
        if perms.startswith("r--"):
            linkedit_vm_off = vm_off
            break
    if text_file_off is None or linkedit_vm_off is None:
        raise RuntimeError(f"could not parse pthread layout from {path}")
    return text_file_off, linkedit_vm_off


def public_pthread_create(dsc):
    proc = subprocess.run(
        [
            "ipsw",
            "dyld",
            "symaddr",
            str(dsc),
            "--image",
            "/usr/lib/system/libsystem_pthread.dylib",
            "--all",
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True,
    )
    for line in proc.stdout.splitlines():
        if "(regular) _pthread_create" in line:
            match = LINE_RE.match(line)
            if match:
                return int(match.group(1), 16)
    raise RuntimeError(f"could not find public _pthread_create in {dsc}")


def exact_symbol_addr(path, symbol):
    pattern = re.compile(rf"(?:^|\s){re.escape(symbol)}(?:\s|$)")
    with path.open("r", errors="replace") as handle:
        for line in handle:
            match = LINE_RE.match(line)
            if not match or match.group(1) == "0x000000000":
                continue
            if pattern.search(line):
                return int(match.group(1), 16)
    raise RuntimeError(f"could not find exact symbol {symbol} in {path}")


def dump_qwords(dsc, addr, count):
    proc = subprocess.run(
        ["ipsw", "dyld", "dump", str(dsc), hex(addr), "--count", str(count), "--addr", "--no-color"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True,
    )
    values = []
    for line in proc.stdout.splitlines():
        match = DUMP_LINE_RE.match(line.strip())
        if match:
            values.append(int(match.group(1), 16))
    if len(values) < count:
        raise RuntimeError(f"could not read {count} qwords at {hex(addr)}:\n{proc.stdout}")
    return values[:count]


def strip_pac(value):
    return value & 0xffffffffff


def validate_objc_class_symbols(dsc, symdump, symbols):
    for key, class_name in OBJC_CLASS_SYMBOLS.items():
        if key not in symbols:
            continue
        class_addr = symbols[key]
        metaclass_addr = exact_symbol_addr(symdump, f"_OBJC_METACLASS_$_{class_name}")
        class_ro_addr = exact_symbol_addr(symdump, f"__OBJC_CLASS_RO_$_{class_name}")
        qwords = dump_qwords(dsc, class_addr, 5)
        isa = strip_pac(qwords[0])
        data = strip_pac(qwords[4])
        if isa != metaclass_addr or data != class_ro_addr:
            raise RuntimeError(
                f"{key}: {hex(class_addr)} failed ObjC class layout validation "
                f"(isa={hex(isa)} expected={hex(metaclass_addr)}, "
                f"data={hex(data)} expected={hex(class_ro_addr)})"
            )


def jsc_pthread_create_stub(dsc):
    proc = subprocess.run(
        [
            "ipsw",
            "dyld",
            "macho",
            str(dsc),
            "/System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore",
            "--stubs",
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True,
    )
    for line in proc.stdout.splitlines():
        if line.rstrip().endswith(": _pthread_create"):
            match = re.match(r"^(0x[0-9a-fA-F]+)\s+=>", line)
            if match:
                return int(match.group(1), 16)
    raise RuntimeError(f"could not find JavaScriptCore _pthread_create stub in {dsc}")


def gpu_singleton_from_func(dsc, addr):
    proc = subprocess.run(
        ["ipsw", "dyld", "disass", str(dsc), "--vaddr", hex(addr), "--quiet", "--count", "20"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True,
    )
    lines = proc.stdout.splitlines()
    for idx, line in enumerate(lines):
        adrp = re.search(r"adrp\s+x0,\s*(0x[0-9a-fA-F]+)", line)
        if not adrp:
            continue
        for next_line in lines[idx + 1 : idx + 4]:
            add = re.search(r"add\s+x0,\s*x0,\s*#(0x[0-9a-fA-F]+|\d+)", next_line)
            if add:
                return int(adrp.group(1), 16) + int(add.group(1), 0)
    raise RuntimeError(f"could not derive GPUProcess singleton data from {hex(addr)} in {dsc}")


def pkcontact_once_from_func(dsc, addr):
    proc = subprocess.run(
        ["ipsw", "dyld", "disass", str(dsc), "--vaddr", hex(addr), "--quiet", "--count", "20"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True,
    )
    for line in proc.stdout.splitlines():
        match = re.search(r"add\s+x0,\s*x0,\s*#(0x[0-9a-fA-F]+|\d+)", line)
        if not match:
            continue
        prev = proc.stdout[: proc.stdout.find(line)].splitlines()[-3:]
        for prev_line in reversed(prev):
            adrp = re.search(r"adrp\s+x0,\s*(0x[0-9a-fA-F]+)", prev_line)
            if adrp:
                once = int(adrp.group(1), 16) + int(match.group(1), 0)
                return once, once + 8
    raise RuntimeError(f"could not derive initPKContact once/value from {hex(addr)} in {dsc}")


def cache_offset(dsc, addr):
    proc = subprocess.run(
        ["ipsw", "dyld", "a2o", str(dsc), hex(addr)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True,
    )
    match = re.search(r"Offset\s+dec=\d+\s+hex=(0x[0-9a-fA-F]+)", proc.stdout)
    if not match:
        raise RuntimeError(f"could not parse a2o output for {hex(addr)}:\n{proc.stdout}")
    return int(match.group(1), 16)


def fmt(value):
    return f"0x{value:x}n"


def main():
    report = {}
    for tag, meta in TARGETS.items():
        symdump = WORK / f"{tag}_symaddr_all.txt"
        if not symdump.exists():
            raise SystemExit(f"missing symbol dump: {symdump}")
        if not meta["dsc"].exists():
            raise SystemExit(f"missing DSC: {meta['dsc']}")
        symbols, missing = read_symbols(symdump)
        validate_objc_class_symbols(meta["dsc"], symdump, symbols)
        if "GPUProcess_singleton" not in symbols and "GPUProcess_singleton_func" in symbols:
            symbols["GPUProcess_singleton"] = gpu_singleton_from_func(meta["dsc"], symbols["GPUProcess_singleton_func"])
            missing = [item for item in missing if item != "GPUProcess_singleton"]
        symbols.pop("GPUProcess_singleton_func", None)
        missing = [item for item in missing if item != "GPUProcess_singleton_func"]
        if (
            ("WebCore__initPKContact_once" not in symbols or "WebCore__initPKContact_value" not in symbols)
            and "WebCore__initPKContact_func" in symbols
        ):
            once, value = pkcontact_once_from_func(meta["dsc"], symbols["WebCore__initPKContact_func"])
            symbols["WebCore__initPKContact_once"] = once
            symbols["WebCore__initPKContact_value"] = value
            missing = [
                item for item in missing
                if item not in ("WebCore__initPKContact_once", "WebCore__initPKContact_value")
            ]
        symbols.pop("WebCore__initPKContact_func", None)
        missing = [item for item in missing if item != "WebCore__initPKContact_func"]
        if (
            "WebCore__softLinkDDDFACacheCreateFromFramework" not in symbols
            and "WebCore__softLinkDDDFAScannerFirstResultInUnicharArray" in symbols
        ):
            symbols["WebCore__softLinkDDDFACacheCreateFromFramework"] = (
                symbols["WebCore__softLinkDDDFAScannerFirstResultInUnicharArray"] + 8
            )
            missing = [item for item in missing if item != "WebCore__softLinkDDDFACacheCreateFromFramework"]
        if "JavaScriptCore__globalFuncParseFloat" in symbols:
            symbols["jsc_base"] = image_base_for_symbol(meta["dsc"], JSC_IMAGE, symbols["JavaScriptCore__globalFuncParseFloat"])
        text_file_off, linkedit_vm_off = pthread_image_layout(tag)
        pthread_create = public_pthread_create(meta["dsc"])
        pthread_offset = cache_offset(meta["dsc"], pthread_create) - text_file_off
        libsystem_pthread_base = pthread_create - pthread_offset
        symbols["pthread_create"] = pthread_create
        symbols["pthread_create_offset"] = pthread_offset
        symbols["libsystem_pthread_base"] = libsystem_pthread_base
        symbols["libsystem_pthread_linkedit"] = libsystem_pthread_base + linkedit_vm_off
        if "jsc_base" in symbols:
            pthread_create_jsc = jsc_pthread_create_stub(meta["dsc"])
            symbols["pthread_create_jsc"] = pthread_create_jsc
            symbols["pthread_create_auth_stubs_offset"] = pthread_create_jsc - symbols["jsc_base"]
        report[tag] = {
            "ios": meta["ios"],
            "device_key": meta["device_key"],
            "symbols": {key: fmt(value) for key, value in sorted(symbols.items())},
            "missing_symbol_patterns": missing,
            "manual_required": [
                "JOP gadget byte-pattern matches: gadget_control_*, gadget_loop_*, gadget_set_all_registers_*",
                "non-symbol string/data anchors such as HOMEUI_cstring, PerfPowerServicesReader_cstring, libARI_cstring, libGPUCompilerImplLazy_cstring",
            ],
        }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    sys.exit(main())
