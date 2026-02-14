# Compliance Scanner
A Python-based security and compliance scanner for detecting risks in code.

## Current Features
- Scans directories for Python files
- **File permission checking (Linux/Mac/WSL)**
- Detects hardcoded secrets (passwords, API keys, tokens)
- Reports file location and line number of vulnerabilities
- Exports results to JSON with timestamp and metadata

## Platform Support
- **Windows**: Secrets detection works fully. File permission checks skipped (Windows uses different security model).
- **Linux/Mac/WSL**: All features work including file permission analysis.

## Usage
```bash
python scanner.py
```

Results saved to `scan_results.json`

## Example Output
```
COMPLIANCE SCANNER - Security Analysis
============================================================

📁 Scanning 5 Python files...

✅ Results saved to scan_results.json

🚨 SCAN COMPLETE: Found 2 security issues
============================================================

[1] HIGH SEVERITY
📁 File: ./test.py
📝 Line: 3
🚨 Issue: Hardcoded secret detected
💻 Code: password = "test123"
```

## Roadmap
- [x] Hardcoded secrets detection
- [ ] File permission checking
- [ ] Dependency vulnerability scanning (requirements.txt)
- [ ] Framework compliance mapping (SOC 2, CIS Controls)
- [ ] HTML report generation
