# PkgTruth Example Artifacts & Reproduction Guide

This directory provides real published packages, source trees, and reports demonstrating how PkgTruth evaluates clean versus compromised releases.

## Included Examples

### 1. `clean-package/`
- **Tarball:** `clean-demo-pkg-1.0.0.tgz` (built TypeScript output with dist files, valid sourcemaps, and standard npm metadata).
- **Source Tree:** `source/` (TypeScript source files `src/index.ts`, `tsconfig.json`, `package.json`).
- **Verdict:** **LOW** (Score 5)
- **Report:** `report.json`

To reproduce analysis:
```bash
pkgtruth file examples/clean-package/clean-demo-pkg-1.0.0.tgz \
  --source-dir examples/clean-package/source \
  --json examples/clean-package/report.json
```

### 2. `tampered-package/`
- **Tarball:** `tampered-demo-pkg-1.0.0.tgz` (injected attack payload into `dist/index.js` contacting external C2, added obfuscated file `lib/x.min.js`, and added `postinstall` hook).
- **Source Tree:** `source/` (clean reference repository).
- **Verdict:** **HIGH** (Score 365)
- **Report:** `report.json`

To reproduce analysis:
```bash
pkgtruth file examples/tampered-package/tampered-demo-pkg-1.0.0.tgz \
  --source-dir examples/tampered-package/source \
  --json examples/tampered-package/report.json
```

## Benchmark

See [`benchmark.md`](benchmark.md) for results of running the mutation benchmark harness across 50 packages (20 clean, 30 mutated).
To re-run the benchmark suite:
```bash
python3 tools/mutate.py
```
