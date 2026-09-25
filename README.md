# Mandate Order — Thai translation mod installer (source)

Source code for `MOThaiInstaller.exe`, the installer shipped with the Thai
translation mod for **Mandate Order** (Steam app 1733690, Digital Sky).

This repository exists so the build can be reproduced and reviewed. The
released archive contains a compiled `.exe`, which Nexus Mods quarantines
automatically; the executable's behaviour is documented in full below so a
reviewer does not have to reverse it.

## What the executable does

The installer is a single Win32 GUI program. It does **not** download anything,
does **not** touch the network, does **not** write to the registry, does not
install services, does not inject into running processes, and does not persist
anything outside the game's own folder. It runs with the same rights as the
user — no elevation is requested.

It uses exactly these system APIs, all file-scoped:

```
CreateFileW  ReadFile  WriteFile  DeleteFileW  CreateDirectoryW
GetModuleFileNameW  FindFirstFileW  RegisterClassExW
RegGetValueW                       (read-only, to locate Steam)
```

### Install

1. **Locate the game.** Reads Steam's `InstallPath` (read-only) from
   `HKLM\SOFTWARE\WOW6432Node\Valve\Steam`, `HKLM\SOFTWARE\Valve\Steam` or
   `HKCU\SOFTWARE\Valve\Steam`, then parses the `libraryfolders.vdf` of each
   library folder it finds. The user can also pick the folder manually.
   The install is rejected unless `<game>\MOProject\Binaries\Win64\MOProject-Win64-Shipping.exe`
   and `<game>\MOProject\Content\Paks\` both exist.

2. **Check the game version.** The game executable must be exactly
   `215,169,944` bytes, and the six bytes at file offset `0x264817E` must be
   `0F 85 4C 01 00 00`. If either differs, the installer stops before writing
   anything and says so. This is what keeps the mod from being applied to a
   game build it was not made for.

3. **Back up.** The original executable and the original target `.pak` are
   copied into `_ThaiMod_Backup\` next to the game executable, together with a
   `manifest.txt` recording the original bytes, their offset, and the SHA-256
   of the pristine executable.

4. **Patch six bytes of the executable.** At `0x264817E`, the conditional jump
   `0F 85 4C 01 00 00` (`jne`) is replaced with six `0x90` (NOP) bytes.

   *Why:* Unreal Engine refuses to mount a `.pak` whose signature was not made
   with the game's private key. The mod's `.pak` is unsigned, so this one
   branch — which only decides whether to reject unsigned archives — is
   disabled. Nothing else in the executable is touched. The install refuses to
   continue if the bytes at that offset are not exactly the expected ones, so
   it can never patch a different instruction in a different build.

5. **Write the translation.** The mod's own `.pak` — the Thai localisation and
   the fonts it uses, and nothing else — is written to
   `MOProject\Content\Paks\pakchunk5000_s3-Windows.pak`.

   *Why that file:* in the shipped game this file is an empty 365-byte
   placeholder with a matching `.utoc`, and its name sorts last among the
   game's pak chunks, so it overrides the game's own archives. Replacing it
   means the game's real content files are never modified.

### Uninstall

Reads `manifest.txt`, restores the original `.pak` and the original six bytes
of the executable from the backup, deletes the backup folder, and reports the
restored executable's SHA-256. If the backup is missing, it reports that
plainly instead of guessing — Steam's "Verify integrity of game files" also
restores both files.

### Where the payload lives

The installer carries the `.pak` appended to its own executable, after the end
of the PE image, followed by a 24-byte footer:

```
char     magic[8]   "MOTHAIPK"
uint64   offset     byte offset of the payload from the start of the file
uint64   size       payload length in bytes
```

Windows ignores data past the end of the image, so the executable still runs
normally. The payload is extracted by streaming 1 MB blocks to disk and is
verified against a hard-coded SHA-256 before and after the write.

The payload contains **no game files**. It is a `.pak` built by us with
UnrealPak, holding only the Thai translation (`.locres`) and fonts under
permissive licences (TW-Kai — SIL OFL 1.1 / OGDL 1.0; Playfair Display,
Noto Serif Thai, Noto Sans — SIL OFL 1.1; Roboto, Droid Sans Fallback —
Apache 2.0). The game's own fonts are not redistributed.

## Antivirus scans

The executable is not code-signed, so a few engines flag it heuristically.
VirusTotal reports **3 detections out of 68** for the released
`MOThaiInstaller.exe`, SHA-256
`b62cd920e352d6d043d917daecc5d690d7b1b0fb07ca865278218b218259a99d`:

| Engine | Verdict | Reading |
|---|---|---|
| Bkav Pro | `W32.Malware.4BFE3A59` | heuristic; Bkav flags most unsigned installers |
| CrowdStrike Falcon | `Win/malicious_confidence_60% (D)` | an ML confidence score, not a signature |
| McAfee Scanner | `Ti!B62CD920E352` | generic "unknown file" heuristic — the suffix is this file's own SHA-256 prefix, so no signature matched |

The report is at
<https://www.virustotal.com/gui/file/b62cd920e352d6d043d917daecc5d690d7b1b0fb07ca865278218b218259a99d>.

No engine named a malware family. VirusTotal also tags the file `overlay`,
which is the appended `.pak` described above: a 55 MB high-entropy blob after
the PE image is what the machine-learning verdicts key on, not any observed
behaviour. The remedy for this class of verdict is code signing, which this
mod does not have.

## Build

Requirements: `g++` (MinGW-w64, 64-bit), Python 3 with no extra packages.

```sh
# 1. compile (from this directory)
g++ -O2 -std=c++17 -mwindows -static -static-libgcc -static-libstdc++ \
    -Wl,--no-insert-timestamp \
    MOThaiInstaller.cpp -o MOThaiInstaller.exe \
    -lcomctl32 -lshell32 -lole32 -luuid

# 2. append the payload (path to a .pak built by UnrealPak)
python make_payload.py MOThaiInstaller.exe <path-to>.pak

# 3. assemble the release zip (expects ./licenses/ and ./*.txt beside it)
python package_dist.py
```

`-Wl,--no-insert-timestamp` is not cosmetic. Without it the linker stamps the
PE header with the current time, so two builds of identical source differ in a
few bytes and any SHA-256 published for the released file stops describing it.
With it, rebuilding this source against the same `.pak` reproduces the released
executable byte for byte — verified by building twice and comparing.

`make_payload.py` writes the footer described above. `package_dist.py` writes
a STORED (uncompressed) zip containing the executable, the licence texts and
the readme.

The strings in the GUI and in the log file are Thai, since the mod is for Thai
players; the code and comments are English.

## Licence

The translation and this code are released under **CC BY-NC-SA 4.0**
(see `LICENSE`). Mandate Order and its assets belong to Digital Sky; no game
content is included here or in the released archive.
