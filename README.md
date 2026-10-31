# PkgTruth

**Compare published packages against their source repositories.
Flag releases that gain powers the source never had.**

---

## The Core Idea

Most supply-chain scanners rely on allowlists and known-bad signatures.
PkgTruth takes a different approach: **capability comparison**.

It downloads a published package, checks out the declared source repository,
and diffs the two. Any capability present in the published artifact that is
absent from the source — network calls, filesystem access, dynamic code
execution, install-time scripts — is flagged and scored.

The question isn't *"is this package on a blocklist?"* — it's
*"does this release do anything the source code doesn't?"*

## Why This Matters

The XZ Utils backdoor (CVE-2024-3094) was injected into release tarballs
while the public Git history remained clean. npm account compromises have
turned trusted packages into credential harvesters overnight. In every case,
the published artifact diverged from the source — and nobody noticed until
it was too late.

PkgTruth automates that comparison so you don't have to eyeball diffs
at 2 a.m.

## Installation

```bash
pip install -e .
```

For development (includes pytest):

```bash
pip install -e ".[dev]"
```

## Quick Start

### Compare a local tarball against its source

```bash
pkgtruth file package.tgz --source-dir ./source
```

### Audit a published npm package

```bash
pkgtruth npm express 4.18.2 --json report.json
```

### View a saved report

```bash
pkgtruth report report.json
```

### Generate an HTML report

```bash
pkgtruth html report.json -o report.html
```

## LLM-Powered Explanations (Optional)

PkgTruth can use a local Ollama model to generate human-readable
explanations for each flagged diff. This is entirely optional — the tool
works fully offline with `--no-llm`.

```bash
ollama pull qwen2.5-coder:7b
export PKGTRUTH_MODEL=qwen2.5-coder:7b
pkgtruth npm express 4.18.2 --json report.json
```

Set `PKGTRUTH_MODEL` to any Ollama-compatible model tag.

## Architecture

```
┌──────────┐    ┌──────┐    ┌─────────┐    ┌────────┐    ┌──────────────┐    ┌───────┐    ┌────────┐
│  Resolve  │───▶│ Diff  │───▶│ Explain │───▶│ Detect │───▶│ Capabilities │───▶│ Score │───▶│ Report │
└──────────┘    └──────┘    └─────────┘    └────────┘    └──────────────┘    └───────┘    └────────┘
  Fetch pkg       Tree        LLM or         Pattern       Classify new       Assign       JSON /
  + source        diff        heuristic      matching      powers added       severity     HTML /
  code                        summary        for known                        rating       terminal
                                             bad patterns
```

**Resolve** — Download the published artifact and clone/checkout the source repo.
**Diff** — Produce a tree-level diff of every file in both trees.
**Explain** — Optionally summarize each changed file via LLM or heuristic.
**Detect** — Run pattern detectors for obfuscation, minification mismatches, and known-bad snippets.
**Capabilities** — Classify net-new capabilities (network, filesystem, crypto, eval, install hooks).
**Score** — Assign a severity rating (LOW / MEDIUM / HIGH / CRITICAL) based on findings.
**Report** — Output results as JSON, HTML, or a formatted terminal table.

## Adding a New Ecosystem Plugin

PkgTruth supports multiple package ecosystems through a plugin system.

1. Create a new module in `pkgtruth/ecosystems/`.
2. Subclass `EcosystemPlugin` from `pkgtruth.ecosystems.base`.
3. Implement the required methods: `fetch_package()`, `fetch_source()`,
   and `get_metadata()`.
4. Register the plugin in the ecosystem registry.

```python
from pkgtruth.ecosystems.base import EcosystemPlugin

class CargoPlugin(EcosystemPlugin):
    name = "cargo"

    def fetch_package(self, name: str, version: str, dest: Path) -> Path:
        ...

    def fetch_source(self, metadata: dict, dest: Path) -> Path:
        ...

    def get_metadata(self, name: str, version: str) -> dict:
        ...
```

## Watchlist Monitoring

Create a `watchlist.yml` (see `watchlist.example.yml`) and run:

```bash
pkgtruth watch watchlist.yml --json reports/ --fail-on medium
```

A GitHub Actions workflow (`.github/workflows/monitor.yml`) runs this
daily at 08:00 UTC via cron.

## Limitations

- **No full rebuild verification.** PkgTruth compares file trees, not
  reproducible builds. A sophisticated attacker who also controls the
  source repo can evade detection.
- **Heavily bundled packages may score MEDIUM.** Webpack/esbuild output
  legitimately differs from source. PkgTruth tries to account for common
  bundlers, but some false positives are expected.
- **Valid provenance reduces risk but does not prove safety.** SLSA
  provenance and Sigstore signatures are checked when available, but
  a signed package can still contain malicious code if the build pipeline
  was compromised.
- **LLM explanations are best-effort.** The local model may
  mischaracterize a diff. Always review flagged files manually.

## Team

Built by **NullPointers**.

## License

[MIT](LICENSE)
