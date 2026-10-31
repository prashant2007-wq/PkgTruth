# PkgTruth Detection & Integrity Benchmark

Conducted using `tools/mutate.py` across real compiled npm packages and injected attack variations.

## Summary Results

| Metric | Result | Benchmark Target | Status |
|---|---|---|---|
| **Clean Package Evaluation** | 20 packages | >= 20 | PASS |
| **Tampered Mutant Evaluation** | 30 packages | >= 30 | PASS |
| **Detection Rate** | **100.0%** (30/30) | >= 95% | **EXCELLENT** |
| **False-Alarm Rate** | **0.0%** (0/20) | <= 5% | **EXCELLENT** |

## Evaluated Attack Vectors

1. **Install Hook Injections (`postinstall` / `preinstall`)**
   - Injected lifecycle scripts in `package.json`
   - Detection: `install_hook_added` finding (Weight 40)
   - Result: 100% detection rate

2. **Obfuscated Payload Insertion**
   - Packed eval, dense hex escapes (`\x..`), hex identifiers (`_0x..`), String.fromCharCode
   - Detection: `obfuscation` detector (Weights 25-30)
   - Result: 100% detection rate

3. **Injected Runtime Execution & C2 Exfiltration**
   - Direct injection into compiled `dist/index.js` with `child_process.exec` and novel external domain
   - Detection: `containment` failure + `EXEC` and `NETWORK` gained capabilities
   - Result: 100% detection rate

4. **Unauthorized Dependency Additions**
   - Addition of unreviewed third-party dependency in `dependencies`
   - Detection: `new_dependency` detector (Weight 15)
   - Result: 100% detection rate

5. **Python `.pth` Auto-Execution Hooks**
   - Addition of `.pth` file in package distribution
   - Detection: `pth_file_added` finding (Weight 40)
   - Result: 100% detection rate

## Reproducing Benchmark

Run directly from the repository root:
```bash
python3 tools/mutate.py
```
