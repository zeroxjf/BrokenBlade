# iOS 18.x Firmware Workspace

Repo-local firmware artifacts used for early iOS 18.x offset work.

| Chip | Device | iOS | Build | Source IPSW |
|---|---|---:|---|---|
| A12 | iPhone11,8 | 18.0 | 22A3354 | `iPhone11_8_18.0_22A3354_Restore.ipsw` |
| A13 | iPhone12,1 | 18.1 | 22B83 | `iPhone12_1_18.1_22B83_Restore.ipsw` |
| A14 | iPhone13,2/13,3 | 18.2 | 22C152 | `iPhone13_2_iPhone13_3_18.2_22C152_Restore.ipsw` |
| A15 | iPhone14,5 | 18.3 | 22D63 | `iPhone14_5_18.3_22D63_Restore.ipsw` |
| A16 | iPhone15,2 | 18.2 | 22C152 | `iPhone15_2_18.2_22C152_Restore.ipsw` |
| A17 Pro | iPhone16,1 | 18.3 | 22D63 | `iPhone16_1_18.3_22D63_Restore.ipsw` |
| A18 Pro | iPhone17,1 | 18.0 | 22A3354 | `iPhone17_1_18.0_22A3354_Restore.ipsw` |

Extraction outputs live in `extracted/`. Symbol dumps and derived reports live in `work/`. Raw IPSWs are intentionally discarded after extraction to keep the workspace small.

The chip column is human-readable SoC metadata only: `iPhone13,2/13,3` is the iPhone 12 / iPhone 12 Pro class and uses A14. Runtime `device_chipset` values are opaque per-model profile hashes carried forward from the existing supported tables; they are not inferred from the `iPhoneNN,M` model-number prefix.

Current derived-symbol report:

```bash
python3 tools/extract_ios18_symbol_offsets.py > firmware/work/ios18_symbol_offsets_report.json
```

Current manual byte-pattern/string-anchor report:

```bash
python3 tools/derive_ios18_manual_offsets.py > firmware/work/ios18_manual_offsets_report.json
```

Current merged `rce_offsets` candidate report:

```bash
python3 tools/build_ios18_rce_offset_candidates.py > firmware/work/ios18_rce_offset_candidates.json
```

Current sandbox/bridge offset report:

```bash
python3 tools/derive_ios18_sbx_offsets.py > firmware/work/ios18_sbx_offsets_report.json
```

The reports separate symbol-derived anchors, manually validated byte-pattern/string anchors, and layout-derived constants. Current coverage derives complete 105-key `rce_offsets` records, 40-key `sbx0` MessageName records, and 24-key `sbx1` gadget records for each sampled build, including `pthread_create_jsc`, `pthread_create_auth_stubs_offset`, `pthread_create_offset`, `libsystem_pthread_base`, `libsystem_pthread_linkedit`, the path anchors, `libGPUCompilerImplLazy__invoker`, the GPU slow-call bootstrap JOP gadgets, and the sandbox/bridge gadgets used by `sbx1_main.js`.

End-to-end runtime support for 18.0 - 18.3 is enabled for the sampled device/build fingerprints in `rce_module.js`, `rce_worker_18.6.js`, `sbx0_main_18.4.js`, and `sbx1_main.js`; broader 18.0 - 18.3.x coverage still needs additional device/build sampling.

Spot-check reports for the extra A16/A17 Pro/A18 Pro IPSWs live in:

```bash
firmware/work/ios18_spotcheck_symbol_offsets_report.json
firmware/work/ios18_spotcheck_manual_offsets_report.json
firmware/work/ios18_spotcheck_rce_offset_candidates.json
firmware/work/ios18_spotcheck_sbx_offsets_report.json
```

Those spot-checks found complete derivation coverage for `iPhone15,2_22C152`, `iPhone16,1_22D63`, and `iPhone17,1_22A3354`: 58 symbol anchors, 12 manual anchors, 105 RCE offsets, 40 `sbx0` offsets, and 24 `sbx1` offsets each. Runtime support is not version-only, so these additional device/build fingerprints are enabled through their own `linkedit_to_device`, `device_chipset`, `rce_offsets`, `sbx0_offsets`, and `sbx1_offsets` entries.
