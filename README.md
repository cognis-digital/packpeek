# packpeek

**Static packer / loader fingerprinter (C)** — is this binary packed, and by what?

[![ci](https://github.com/cognis-digital/packpeek/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/packpeek/actions/workflows/ci.yml)
![lang](https://img.shields.io/badge/lang-C-A8B9CC)
![license](https://img.shields.io/badge/license-COCL%201.0-2ea043)

Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)**. The classic first step in malware triage: `packpeek` searches a binary for the documented markers of common runtime packers/protectors — **UPX, ASPack, Themida, WinLicense, MPRESS, PECompact, Petite, FSG, MEW, NsPack, Enigma, VMProtect, Armadillo** — and measures **Shannon entropy**. A packer marker plus high entropy is a strong "this is packed, look closer" signal.

Format-agnostic (PE / ELF / Mach-O / firmware blob), dependency-free, JSON-out. Pairs with [`entroc`](https://github.com/cognis-digital/entroc) for windowed entropy and emits **YARA + SARIF** via the bundled companion.

> Defensive triage only — reads a file, makes no network calls, executes nothing.

## Build

```bash
gcc -O2 -std=c99 -o packpeek packpeek.c -lm
```

## Usage

```
packpeek <file> [--threshold F]
  --threshold   entropy (bits, 0..8) above which a file is "high entropy" (default 7.2)
```

```bash
packpeek suspicious.exe
packpeek suspicious.exe | python sarif.py            # -> SARIF for code scanning
packpeek suspicious.exe | python sarif.py --yara     # -> deployable YARA rule
```

## Output

```json
{"tool":"packpeek","file":"suspicious.exe","size":204800,"entropy":7.91,
 "high_entropy":true,"threshold":7.20,
 "packers":[{"name":"UPX","offset":336}],"packer_count":1,"verdict":"packed"}
```

Exit **2** if `packed`/`likely-packed`, **0** if `clean`, **1** on error — gate CI on it.

## License

COCL 1.0 — see [LICENSE](LICENSE). Commercial use → licensing@cognis.digital
