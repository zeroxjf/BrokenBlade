# Safari 18.3 Tart Lab

This lab is a macOS peer environment for iOS 18.3 WebKit/JSC testing.
It is useful for fast JavaScript, JSC, worker, and diagnostic-logging checks,
but it is not a replacement for real iOS WebContent testing.

## Reference Versions

- iOS point of reference: iOS 18.3 final, build `22D63`.
- Example iOS IPSW anchor: `iPhone14,5_18.3_22D63_Restore.ipsw`.
- macOS peer VM: macOS Sequoia 15.3, build `24D60`.
- Safari/WebKit train: Safari 18.3, build `20620.2.4`.
- Local Tart VM name: `safari-18.3-lab`.

Apple documents Safari 18.3 as available for iOS 18.3, iPadOS 18.3,
visionOS 2.3, macOS 15.3, macOS Sonoma, and macOS Ventura.

## Create The VM

```sh
tart create safari-18.3-lab --from-ipsw \
  https://updates.cdn-apple.com/2025WinterFCS/fullrestores/072-08269/7CAAB9F7-E970-428D-8764-4CD7BCD105CD/UniversalMac_15.3_24D60_Restore.ipsw

tart set safari-18.3-lab --cpu 4 --memory 8192 --display 1440x900
```

## Run The VM

```sh
tart run safari-18.3-lab
```

On first boot, complete Setup Assistant in the VM window.

## Verify Inside The VM

```sh
sw_vers
defaults read /Applications/Safari.app/Contents/Info CFBundleShortVersionString
defaults read /Applications/Safari.app/Contents/Info CFBundleVersion
```

Expected values:

- `ProductVersion`: `15.3`
- `BuildVersion`: `24D60`
- Safari short version: `18.3`
- Safari bundle version: `20620.2.4`

## Scope

Good fit:

- Stage0/JavaScript behavior checks.
- JSC crash timing and logging experiments.
- Worker scheduling and message-flow diagnostics.
- Safari 18.3 train regression comparisons.

Not exact:

- iOS dyld shared cache offsets.
- iOS WebContent sandbox state.
- Device-specific WebCore object layout.
- iOS PAC/signing behavior.

