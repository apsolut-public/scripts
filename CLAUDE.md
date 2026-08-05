# CLAUDE.md — scripts

Independent developer scripts. Each one is a single self-contained file someone can download on its own, or copy-paste into a local file and run.

Repo: <https://github.com/apsolut-public/scripts> (public). Renamed from `cli` — GitHub redirects the old URL, but don't write the old name into anything new.

**Stack:** PowerShell 7+ (`*.ps1`) and bash (`*.sh`). No build, no dependencies, no package manager, no installer.

## The one rule

**This is not a tool.** No shared library, no engine, no data files, no config, no install step. If a change would make one script depend on another file in this repo, don't make it — duplicate the few lines instead. Someone landing on a raw GitHub URL must be able to run what they see.

That means indicator lists, lookup tables, and constants live inline at the top of the script that uses them, under a clearly-marked data block.

## Split with helpers

`helpers` is the sibling repo — a VitePress docs site of CLI cheatsheets. Local checkout: `D:\sites\git\apsolut\helpers`. Published at <https://helpers.apsolut.dev/>.

**The helpers GitHub repo is private.** Never link to `github.com/apsolut/helpers` from anything public in this repo — it 404s for readers. Link to the site instead; deep links take the form `https://helpers.apsolut.dev/shell/power-tools.html`.

- Something you **read** → helpers
- Something you **run** → here

Don't add prose guides to this repo. If a script needs explanation beyond its `--help` and a README section, the explanation goes to helpers and the README links to it.

## Layout

Top-level folders match the sections on helpers.apsolut.dev, so the two repos share one taxonomy:

- `security/` — scanners for supply-chain incidents and similar
- `shell/` — bash / WSL
- `windows/` — PowerShell, Windows-specific fixes
- add `git/`, `docker/`, `wsl/`, `agents/` the same way when something lands there

Name files so the filename alone identifies the job and the platform: `scan-npm-shai-hulud.ps1` reads as "Shai-Hulud, npm, Windows" at a glance. A folder holding thirty incidents must still be scannable by eye. Never name a script `scan.sh` or `setup.sh`.

## Conventions for new scripts

Every script must:

- Be standalone — see The one rule
- Support a dry run — `-WhatIf` via `[CmdletBinding(SupportsShouldProcess)]` in PowerShell, `--dry-run` in bash. Read-only scripts (scanners, reports) are exempt: they're already dry. Give them `--quiet` instead
- Support `--help` / comment-based help explaining what it does and why the approach is what it is
- Be idempotent — safe to run twice
- Back up or refuse before overwriting anything the user owns (see `shell/bashrc-setup.sh`, which copies to `.bak` and edits only between its markers)
- Exit non-zero on failure. Scanners follow the grep convention: `0` = nothing found, `1` = findings, `2` = bad usage
- Ship a PowerShell and a bash version when the job isn't platform-specific, and keep them behaviourally identical — same checks, same counts, same exit codes. Test both against one shared fixture

Bash scripts: `set -uo pipefail`, LF line endings. `.gitattributes` pins `*.sh` to `eol=lf` because `core.autocrlf=true` here — without it a fresh clone gets CRLF and bash dies with `bad interpreter: /bin/bash^M`.

Never use `find ... | while read` to accumulate a counter — the body runs in a subshell and the increments vanish, which in a scanner prints "Clear" directly under a finding. Use `while read ... done < <(find ...)`.

## Testing

There's no test runner. Verify by running:

- PowerShell: parse-check with `[System.Management.Automation.Language.Parser]::ParseFile`, then exercise against throwaway files in a temp dir. Note `Write-Host` output does not go down the pipeline — capturing to a variable to count lines gives 0
- Bash: `wsl -d Ubuntu-22.04 -- bash -s <<'EOF' … EOF` (heredoc via stdin — passing the script as a `-lc` argument mangles variable expansion), plus `bash -n`
- Scanners: build a clean fixture and a dirty fixture with one planted indicator per check. Assert the exact finding count and the exit code, from both language versions, against the same fixture

## Local conventions

Working notes and vault conventions live in `AGENTS.md` — untracked and local only, so it won't be present in a fresh clone.
