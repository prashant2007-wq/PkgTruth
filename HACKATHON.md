# HACKATHON.md

## Team
- **Team name:** NullPointers
- **Members:**
  1. Prashant S. Bisht
  2. Arya Avinash Tiwari
  3. Babita Rathore
- **Event:** Hacktoberfest 2026 Hack Day, Sonipat (NST x Rishihood University)

## Problem statement
**Problem 4: Published Package vs Source Code Integrity Analyzer**

## Project: PkgTruth
A tool that checks whether a published npm package matches its source repository, explains every difference, and flags releases that gain powers the source never had.

**Core idea:** a release is trusted only if it adds no capability (network access, process execution, eval, install hooks, new dependencies) that its source does not have. No hardcoded allowlist of "normal" files.

## Models used, and why

| Model | Runs via | Why |
|---|---|---|
| `qwen2.5-coder:7b` (open-weight) | Ollama, locally | Reads unexplained or suspicious code snippets and writes a plain-English explanation. It must quote exact lines from the file, and our code verifies each quote exists. Anything it cannot ground is discarded. It is a supporting signal only. |

- All scoring decisions are made by deterministic code. The model explains and gives a second opinion, it never decides alone.
- If the model is unavailable, the tool falls back to template explanations and still works.
- No closed or cloud AI APIs are used inside the product.

## AI coding assistants used while building
- **Google Antigravity:** website/dashboard and project scaffolding
- **Claude Sonnet (Anthropic):** helped write and review code, tests and the dashboard. Not used inside the product.

Every pull request names the models and assistants used in that change.

## What we are building
1. **Fetch and resolve:** download the package from npm (or load a local tarball), find its repo and the matching tag or commit.
2. **Diff:** compare package files to source files, bucket them as identical, modified, added or missing.
3. **Capability check:** extract what the code can do from both sides and flag anything the package gains.
4. **Install-hook and dependency checks:** new `preinstall` / `postinstall` scripts, added dependencies.
5. **Provenance signals:** missing tag or commit, missing attestation.
6. **Risk score and report:** LOW / MEDIUM / HIGH with file, line and reason as evidence, as JSON and a readable report.
7. **Dashboard website:** static page that loads the JSON report and shows the verdicts and evidence.
8. **Stretch:** release history baseline, attack mutator with a benchmark table, PyPI plugin, scheduled monitoring.

## Planned project structure
```
.
├── HACKATHON.md
├── README.md
├── LICENSE                      # MIT
├── pyproject.toml
├── .github/
│   ├── pull_request_template.md
│   └── workflows/
│       ├── ci.yml               # install + run tests on every PR
│       └── monitor.yml          # scheduled release watcher
├── pkgcheck/
│   ├── cli.py                   # pkgcheck npm <name> <ver> | pkgcheck file <tarball> --repo <url>
│   ├── ecosystems/              # npm.py, pypi.py (one plugin per ecosystem)
│   ├── source.py                # repo, tag and commit resolution
│   ├── diff.py                  # file tree comparison
│   ├── explainers/              # sourcemap, config, containment, metadata-only
│   ├── detectors/               # install hooks, obfuscation, behavior, dependencies
│   ├── capabilities.py          # capability extraction and comparison
│   ├── score.py                 # weighted risk scoring
│   ├── report.py                # JSON and text output
│   └── llm.py                   # Ollama wrapper with grounded quotes and fallback
├── website/                     # static dashboard (HTML/CSS/JS), reads report JSON
├── tests/                       # one test per attack scenario
├── examples/
│   ├── clean-package/           # input + real output
│   └── tampered-package/        # input + real output
└── tools/
    └── mutate.py                # builds tampered copies for benchmarking
```

## Tech stack
Python 3.11, pytest, Ollama, `qwen2.5-coder:7b`, npm registry API, Git, GitHub Actions, static HTML/CSS/JS dashboard.

## Rules we follow
- New empty public repo, MIT license, `HACKATHON.md` as the first commit.
- Every change after that goes through a pull request with CI.
- Public data only. No automated comments or issues on real projects.
- No API keys or secrets in the repo
