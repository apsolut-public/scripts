# 🧰 scripts

Independent developer scripts. Take the one you want — nothing here depends on anything else here.

> Things that took me way too long to figure out — now with a `--help` flag.

**Not a tool.** No install, no framework, no config, no shared library. Every script is a single self-contained file: download it, or open it and copy-paste it into a local file. If you want the NUL fix, take the NUL fix. If you want the supply-chain scan, take that. Nothing else comes with it.

Companion to [helpers.apsolut.dev](https://helpers.apsolut.dev/): that's the **docs** — searchable cheatsheets for git, shell, PowerShell, Windows, WSL, agents. This is the **executables**. If it's something you read, it belongs there. If it's something you run, it belongs here.

---

## 📂 Scripts

Folders match the sections on [helpers.apsolut.dev](https://helpers.apsolut.dev/) — read it there, run it from here.

| Script | Platform | What it does |
|--------|----------|--------------|
| [`security/scan-npm-shai-hulud.ps1`](./security/scan-npm-shai-hulud.ps1) | Windows | Scans for Shai-Hulud npm supply-chain indicators of compromise |
| [`security/scan-npm-shai-hulud.sh`](./security/scan-npm-shai-hulud.sh) | Linux / macOS / WSL | Same scan, same checks, same exit codes |
| [`windows/nuke-nul.ps1`](./windows/nuke-nul.ps1) | Windows | Deletes files with reserved device names (`nul`, `con`, `aux`, `com0-9`, `lpt0-9`) that Explorer and `del` both refuse to touch |
| [`windows/trim-context-menu.ps1`](./windows/trim-context-menu.ps1) | Windows | Makes the Explorer right-click menu fast by blocking the shell extensions you never use — reversible, nothing deleted |
| [`windows/trim-startup.ps1`](./windows/trim-startup.ps1) | Windows | Shows what Windows blamed for your slow boots and defers startup junk — services to Manual, logon tasks and Run entries disabled, all restorable |
| [`shell/bashrc-setup.sh`](./shell/bashrc-setup.sh) | WSL2 / bash | Writes the power-tools block into `~/.bashrc` — zoxide, atuin, direnv, fzf, oh-my-posh + eza/bat/lazygit aliases |

`.ps1` = Windows/PowerShell. `.sh` = bash. The filename says which incident or job it handles, so a folder full of them stays readable.

---

## 🚀 Getting one

**Download just the file you want:**

```powershell
irm https://raw.githubusercontent.com/apsolut-public/scripts/main/security/scan-npm-shai-hulud.ps1 -OutFile scan.ps1
.\scan.ps1 -Path D:\sites
```

```bash
curl -fsSLO https://raw.githubusercontent.com/apsolut-public/scripts/main/security/scan-npm-shai-hulud.sh
bash scan-npm-shai-hulud.sh ~/sites
```

**Or open it on GitHub, copy, paste into a local file, run it.** Every script is written to survive that — no imports, no companion files, no setup step.

Read before you run, especially the security ones. They're short on purpose.

---

## 🚨 scan-npm-shai-hulud

Scans local or checked-out projects for indicators of compromise from the **Shai-Hulud** npm supply-chain attacks — the [August 2026 wave](https://www.aikido.dev/blog/keyv-and-friends-compromised-in-npm-supply-chain-attack) that hit `keyv`, `cacheable`, `cache-manager`, `ecto` and friends, plus payload filenames carried over from the November 2025 wave.

```powershell
.\scan-npm-shai-hulud.ps1 -Path D:\sites   # everything under a projects root
.\scan-npm-shai-hulud.ps1 -Quiet           # findings only
.\scan-npm-shai-hulud.ps1 -Deep            # also sweep node_modules in check 6
```
```bash
./scan-npm-shai-hulud.sh ~/sites
./scan-npm-shai-hulud.sh --quiet
./scan-npm-shai-hulud.sh --deep
```

Six checks, read-only — nothing is modified, deleted, or quarantined:

1. **Payload files** by name (`setup.mjs`, `math_init.js`, `Math_Symbol.js`, `setup_bun.js`, `bun_environment.js`) — SHA-256 printed with each hit
2. **`preinstall` hooks** in any `package.json` that launch a payload
3. **Compromised versions** under `node_modules` — all 11 primary packages, scoped names (`@cacheable/memory`) included, nested `node_modules` resolved to the right package
4. **GitHub Actions workflows** dumping the whole secrets context (`toJSON(secrets)`)
5. **IDE persistence** written into `.vscode/tasks.json` or `.claude/settings.json`
6. **Exfiltration strings** — the fallback domain, the `Shai-Hulud: Here We Go Again` campaign marker, the wallet address

**Exit `0` when nothing is found, `1` on findings, `2` on bad usage** — so it drops straight into CI or a pre-commit hook.

### Speed

Walking the disk is the whole cost. On a real `D:\sites` with **7.5 million files**, one full traversal takes about 5.6 minutes — so the script does exactly **one**, with `dir` redirecting to a list file on disk. Every check is then a sequential `findstr` over that list, which costs seconds instead of another walk.

Nothing is ever piped into a PowerShell array. Building a 7.5M-element array plus a hashtable keyed on every path is multiple GB, and it's what makes naive versions run for hours or die. If you write your own, also avoid `Get-ChildItem -Recurse -Include` — measured ~8× slower than native `dir` on a mere 5,638-file tree, and it degrades from there.

`-Deep` / `--deep` adds `node_modules` to check 6's content sweep. It's off by default because on a vendored tree that one sweep dominates everything else, while checks 1–3 already cover malicious packages by filename and by version. The number of skipped files is always printed — nothing is silently truncated.

Two Windows gotchas encoded in the script, both of which cause **silent false negatives**:

- `findstr /f:<list>` matches nothing with long absolute paths, while the same files passed as arguments match fine. Files go in as batched arguments instead.
- A `/c:` pattern containing `@` (as in `@cacheable/memory`) matches nothing. Scoped package names are resolved in PowerShell rather than by pattern.

### False positives

`regenerate-unicode-properties` — a very common transitive dependency — genuinely ships a file called `Math_Symbol.js`. Those are recognised and reported as `ignored:` with a count, not as findings, **unless the hash matches a known-bad sample**. A real payload planted at that path is still reported.

Scanning a tree that contains this repo will flag the scripts and this README under check 6 — they carry the indicator strings by definition. Each script skips its own file, but not its sibling.

A payload filename is reported whether or not its hash matches. A matching hash confirms the exact published sample; a **non-matching hash means an unknown variant, not a clean file**. Triage every hit by hand, and rotate npm/GitHub/cloud tokens before writing one off as a false positive.

Indicators live in one clearly-marked block at the top of each file. When new ones are published, that block is the only thing that changes.

For known, catalogued vulnerabilities, use [osv-scanner](https://github.com/google/osv-scanner) or `npm audit` — they're maintained and complete. This is for the first days of a fresh incident, when the indicators are in a blog post and no scanner has ingested them yet.

### 🙏 Credit

The August 2026 indicators — the affected packages and their exact versions, the payload filenames, the SHA-256 hashes, and the exfiltration infrastructure — were researched and published by **[Aikido Security](https://www.aikido.dev/)**:

> [keyv and friends compromised in npm supply chain attack](https://www.aikido.dev/blog/keyv-and-friends-compromised-in-npm-supply-chain-attack)

That post is how I found out about the attack in the first place, and these scripts do nothing more than automate checking for what their research turned up. Thank you.

The credit is repeated inside both scripts, so it travels with the file when someone downloads or copy-pastes just the one.

---

## 🗑️ nuke-nul.ps1

AI coding tools (Cursor, Copilot, and friends) occasionally create a file literally named `nul`. Windows treats that as a device, not a file, so Explorer and a plain `del` both refuse. The escape hatch is the `\\?\` prefix, which skips Win32 path parsing and hands the raw path to the filesystem.

```powershell
.\nuke-nul.ps1                          # scan current directory
.\nuke-nul.ps1 -Path D:\sites -Recurse  # scan a whole tree
.\nuke-nul.ps1 -Recurse -WhatIf         # show what would go, delete nothing
```

Matches reserved names with or without an extension, so `nul.txt` counts too. Exits `1` if any deletion failed — if that happens, re-run in an elevated PowerShell.

Git already refuses to track reserved names, so these never reach a remote. They just clutter `git status`.

Written up at [helpers.apsolut.dev/windows/remove-nul](https://helpers.apsolut.dev/windows/remove-nul.html).

---

## 🖱️ trim-context-menu.ps1

A slow right-click is almost never Explorer. Every shell extension registered for what you clicked — Dropbox, Google Drive, OneDrive, antivirus, NVIDIA, PowerToys, Copilot — gets its DLL loaded and asked for menu items before the menu draws. One slow handler stalls the menu every time.

```powershell
.\trim-context-menu.ps1 -List      # read-only: every handler on this machine, with CLSID and status
.\trim-context-menu.ps1 -WhatIf    # show what would be hidden
.\trim-context-menu.ps1            # hide it (elevated shell also hides HKLM verbs)
.\trim-context-menu.ps1 -Restore   # put it all back
```

Handlers are blocked by CLSID under `HKCU\…\Shell Extensions\Blocked`, which covers both the classic menu and Windows 11's packaged items. It's per-user, needs no admin, and survives the app re-registering itself on update. Plain verbs like *Git Bash Here* or *WSL* get a `LegacyDisable` value instead. Nothing is deleted. Every value carries a `trim-context-menu` tag, `-Restore` removes only tagged values, and anything you'd already blocked yourself is left alone.

The defaults keep 7-Zip, Notepad++, Open with, Copy as path, Pin and New. What gets hidden is one data block at the top of the file. Run `-List`, then edit that block to taste.

---
## 🚀 trim-startup.ps1

Slow boots on fast SSDs are almost always software. Windows already times every boot and records which processes delayed it — nothing shows you. `-List` does, along with what actually starts with Windows.

```powershell
.\trim-startup.ps1 -List                     # boot times, what Windows blamed, AV status, what starts (elevated for boot data)
.\trim-startup.ps1 -WhatIf                   # what the defaults would change
.\trim-startup.ps1                           # apply (elevated)
.\trim-startup.ps1 -Service 'Foo*' -RunEntry 'Spotify' -Task '\Vendor\*'   # add your own
.\trim-startup.ps1 -Restore                  # put everything back
```

What it catches that Task Manager doesn't:

- **Two antivirus engines.** A third-party AV that's installed but expired or off still loads its drivers, while Defender runs full scanning beside it. `-List` flags it. The script never touches security software, so reactivate or uninstall the AV yourself.
- **Logon scheduled tasks.** Task Manager's Startup tab doesn't show them, so an app you "disabled" there (OneDrive is the classic) keeps launching.
- **Vendor services on Automatic** that only matter while their app is open. They go to Manual and still start on demand.

Run entries are disabled the way Task Manager does it, so they show as *Disabled* there. Before any change the original value is saved to `%LOCALAPPDATA%\trim-startup\state.json`, and `-Restore` puts it back. Defaults are wildcard patterns in a data block at the top. Measure with **Restart**, not Shut down — with Fast Startup on, Shut down skips the full boot Windows times.

---
## 🐚 bashrc-setup.sh

```bash
./bashrc-setup.sh --dry-run     # print the block, change nothing
./bashrc-setup.sh               # write it into ~/.bashrc (backs up to ~/.bashrc.bak first)
./bashrc-setup.sh --remove      # strip it back out
OMP_THEME=atomic ./bashrc-setup.sh
```

The block sits between markers, so re-running replaces it rather than appending a second copy. Everything outside the markers is left byte-identical.

Every line is guarded by `command -v`, so a tool you haven't installed contributes nothing and the block never breaks a fresh shell. It also handles the packaging quirks: Debian/Ubuntu's `batcat` and `exa` binary names, and `fzf --bash` on fzf ≥ 0.48 versus sourcing `key-bindings.bash` on older builds.

It installs the *shell wiring*, not the tools themselves. For what each tool does, see [WSL2 Bash power tools](https://helpers.apsolut.dev/shell/power-tools.html).

---

## 🤝 Contributing

New script? Drop it in the folder that matches its topic, add a row to the table, and keep it **standalone** — one file, no imports, no companion data, runnable straight after a copy-paste. Give it `--help` and a dry-run flag where it changes anything.

Name it so the filename alone says what it is (`scan-npm-shai-hulud`, not `scan`). A folder of thirty scripts should still be readable.

Prose, cheatsheets, and command references go to [helpers.apsolut.dev](https://helpers.apsolut.dev/) instead.

---

<p align="center">Created with ♥ by <a href="https://github.com/apsolut/">AP</a></p>
