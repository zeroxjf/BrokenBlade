# BrokenBlade

**[zeroxjf.github.io/BrokenBlade](https://zeroxjf.github.io/BrokenBlade/)**

iOS 18.x userland exploit-chain research project with JavaScript injection that modifies SpringBoard and other system processes at runtime. Based on CVE patch levels, the theoretical iOS 18 vulnerability window is 18.0 - 18.6.2; bundled runtime offsets cover iOS 18.4 - 18.6.2 plus sampled early-build support for 18.0 - 18.3. Open source, derived from [DarkSword](https://iverify.io/blog/darksword-ios-exploit-kit-explained) with all malware communication stripped.

> **This is not tweak injection.** It is runtime JS modification through an exploit chain. Changes persist until respring or reboot - this is not dylib injection like a full jailbreak.

## Supported devices

The theoretical device class is every arm64e iPhone (A12 - A18 Pro) running iOS 18.0 - 18.6.2.

Bundled offset-backed runtime support covers every arm64e iPhone (A12 - A18 Pro) running iOS 18.4 - 18.6.2, plus the sampled early-build devices below:

| iOS | Build | Runtime status |
|---|---:|---|
| 18.0 | 22A3354 | Bundled sampled offsets: A12 `iPhone11,8`, A18 Pro `iPhone17,1` |
| 18.1 | 22B83 | Bundled sampled offsets: A13 `iPhone12,1` |
| 18.2 | 22C152 | Bundled sampled offsets: A14 `iPhone13,2/13,3`, A16 `iPhone15,2` |
| 18.3 | 22D63 | Bundled sampled offsets: A15 `iPhone14,5`, A17 Pro `iPhone16,1` |
| 18.4 | 22E240 | Bundled |
| 18.4.1 | 22E252 | Bundled |
| 18.5 | 22F76 | Bundled |
| 18.6 | 22G86 | Bundled |
| 18.6.1 | 22G90 | Bundled |
| 18.6.2 | 22G100 | Bundled |

The early-build sampling intentionally staggers OS versions across hardware generations. Device model prefixes are not SoC names: `iPhone13,2/13,3` is A14 hardware, and the runtime `device_chipset` hashes are existing per-model profile identifiers rather than labels derived from the visible model number.

## Roadmap

> **To do**
>
> - [ ] Improve chain reliability and reproducibility
> - [ ] Broaden iOS 18.0 - 18.3.x offsets beyond the sampled early-build devices
> - [ ] Get StatBar functional (data reporting works but UI display hits nonstop PAC violations)
> - [ ] Resolve compatibility issues with Nugget and similar tools

> **Done**
>
> - [x] Full WebContent RCE → kernel R/W → sandbox escape chain
> - [x] SBCustomizer (dock icons, home grid columns/rows, hide labels)
> - [x] Powercuff battery saver (4 throttle levels via thermalmonitord)
> - [x] Multi-tweak picker with single chain execution
> - [x] Offset-backed support for every arm64e iPhone on iOS 18.4 - 18.6.2
> - [x] Sampled offset-backed support for A12/A13/A14/A15/A16/A17 Pro/A18 Pro on early iOS 18 builds
> - [x] #cloutfarmed

## How it works

BrokenBlade chains a WebContent RCE into kernel R/W via sandbox escape, then uses a JSC + `objc_msgSend` / `dlsym` native bridge to inject JavaScript into other processes (SpringBoard, mediaplaybackd, thermalmonitord, etc.).

### Chain stages

| Stage | Where | What |
|---|---|---|
| `index.html` | Safari main page | Install card UI, tweak picker, gating |
| `rce_loader.js` | WebContent iframe | URL parser, postMessage routing, exploit bootstrap |
| `rce_worker*.js` | WebContent worker | JavaScriptCore exploit, addrof/fakeobj/read64/write64 primitives |
| `rce_module*.js` | WebContent worker | Heap shaping, PAC gadget signing |
| `sbx0_main_18.4.js` | WebContent worker | Sandbox escape |
| `sbx1_main.js` | mediaplaybackd | Prelude builder, kernel R/W, process injection bridge |
| `pe_main.js` | mediaplaybackd | Payload dispatch, `inject*Payload` helpers |
| `*_light.js` | Target processes | Tweak payloads (run via the native bridge) |

## Available tweaks

### SBCustomizer

Runtime SpringBoard layout customization: dock icon count, home screen columns and rows, hide icon labels. Patched once during chain execution.

### Powercuff

Port of [rpetrich's Powercuff](https://github.com/rpetrich/Powercuff). Underclocks CPU/GPU via thermalmonitord for extended battery life. Four levels: nominal, light, moderate, heavy. Lasts until reboot.

## Usage

Visit [zeroxjf.github.io/BrokenBlade](https://zeroxjf.github.io/BrokenBlade/) in Safari on a supported device. Pick your tweaks, tap **Install Selected**, and keep Safari in the foreground for up to 60 seconds while the chain runs.

**If it fails** (page flash, "A problem repeatedly occurred", or "webpage crashed" banner): clear Safari's cache (book icon > Clear), reload, and retry. If it keeps failing, reboot, clear cache again, and try once more.

## Debugging with syslog.py

`syslog.py` is a filtered device syslog viewer that shows only chain-relevant log lines. Requires a Mac with `idevicesyslog` installed (`brew install libimobiledevice`) and the device connected via USB.

```bash
python3 syslog.py
```

Each run creates a timestamped log file in `logs/` (e.g. `logs/syslog_2026-04-09_15-37-00.txt`). Log tags are color-coded:

- **Green** `[PE]` `[PE-DBG]` - post-exploit / kernel phase
- **Magenta** `[SBX1]` `SBX0` - sandbox escape stages
- **Cyan** `[SBC]` `[POWERCUFF]` `[MG]` `[APPLIMIT]` `[THREEAPP]` - tweak payloads
- **Red** - crashes, PAC violations, JS errors

See [`logs/example_successful_run.txt`](logs/example_successful_run.txt) for what a successful chain run looks like.

## Project structure

```
index.html              Main install page (Safari UI)
frame.html              Exploit iframe shell
rce_loader.js           Iframe-side bootstrap + postMessage router
rce_worker.js           WebContent worker (iOS 18.4-18.5 path)
rce_worker_18.6.js      WebContent worker (iOS 18.6-18.6.2 path)
rce_module.js           Heap shaping module (iOS 18.4-18.5 path)
rce_module_18.6.js      Heap shaping module (iOS 18.6-18.6.2 path)
sbx0_main_18.4.js       Sandbox escape
sbx1_main.js            Kernel R/W + process injection bridge
pe_main.js              Payload dispatch in mediaplaybackd
powercuff_light.js      Powercuff payload
sbcustomizer_light.js   SBCustomizer payload
colorbanners_light.js   ColorBanners payload (WIP)
syslog.py               Device syslog capture helper
```

## Credits

- [iVerify](https://iverify.io/blog/darksword-ios-exploit-kit-explained) & [Google GTIG](https://cloud.google.com/blog/topics/threat-intelligence/darksword-ios-exploit-chain) — DarkSword chain documentation
- [leminlimez](https://github.com/leminlimez/Nugget) — Nugget (MobileGestalt + BookRestore)
- [khanhduytran0](https://github.com/khanhduytran0/SparseBox) — SparseBox (3-app limit bypass)
- [rpetrich](https://github.com/rpetrich/Powercuff) — Powercuff tweak
- [34306](https://github.com/34306) & [khanhduytran0](https://github.com/khanhduytran0) — [site design](http://34306.lol/darksword/) reference
- [@cro4js](https://twitter.com/cro4js) — UI suggestions

## License

MIT License. See [LICENSE](LICENSE) for details.
