import os
import re
import json
import stat
from datetime import datetime

def scan_directory(path):
    """Scan directory and find all Python files"""
    python_file = []
    for root, dirs, files in os.walk(path):
        for file in files:
            if file.endswith(".py"):
                full_path = os.path.join(root, file)
                python_file.append(full_path)
    return python_file

def check_file_permissions(filepath):
    """Check if file has dangerous permissions"""
    findings = []

     # Skip permission checks on Windows
    if os.name == 'nt':  # nt = Windows
        return findings
    try:
        file_stat = os.stat(filepath)
        # Get permission in octal format (e.g., '0o755')
        permissions = oct(file_stat.st_mode)
        
        # Extract last 3 digits (actual permission number)
        perm_digits = permissions[-3:]
        
        # Check for dangerous permissions
        # 777 = everyone can read, write, execute (DANGEROUS)
        # 666 = everyone can read and write (DANGEROUS)
        if perm_digits in ['777', '666']:
            findings.append({
                'file': filepath,
                'issue': f'Dangerous file permissions ({perm_digits})',
                'severity': 'HIGH',
                'permissions': perm_digits,
                'recommendation': 'Change to 644 (owner write, others read only)'
            })
        # 775 or 664 = group has write access (MEDIUM risk)
        elif perm_digits in ['775', '664']:
            findings.append({
                'file': filepath,
                'issue': f'Overly permissive file permissions ({perm_digits})',
                'severity': 'MEDIUM',
                'permissions': perm_digits,
                'recommendation': 'Consider restricting group write access'
            })
    except Exception as e:
        print(f"Error checking permissions for {filepath}: {e}")
    
    return findings

def secret_pattern(filepath):
    """Scan file for hardcoded secrets"""
    findings = []
    secrets = [
        r'password\s*=\s*["\'](.+?)["\']',
        r'token\s*=\s*["\'](.+?)["\']',
        r'api_key\s*=\s*["\'](.+?)["\']',
        r'secret\s*=\s*["\'](.+?)["\']'
    ]
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            for line_num, line in enumerate(content.split('\n'), 1):
                for pattern in secrets:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            'file': filepath,
                            'line': line_num,
                            'issue': 'Hardcoded secret detected',
                            'severity': 'HIGH',
                            'code': line.strip()
                        })
    except Exception as e:
        print(f"Error scanning {filepath}: {e}")
    
    return findings

def main():
    print("="*60)
    print("COMPLIANCE SCANNER - Security Analysis")
    print("="*60)
    
    files = scan_directory(".")
    print(f"\n📁 Scanning {len(files)} Python files...\n")
    
    # Run all checks
    all_findings = []
    
    for file in files:
        # Check 1: File permissions
        perm_results = check_file_permissions(file)
        all_findings.extend(perm_results)
        
        # Check 2: Hardcoded secrets
        secret_results = secret_pattern(file)
        all_findings.extend(secret_results)
    
    # Create report with metadata
    report = {
        "scan_time": datetime.now().isoformat(),
        "total_files_scanned": len(files),
        "total_issues_found": len(all_findings),
        "findings": all_findings
    }
    
    with open("scan_results.json", "w") as f:
        json.dump(report, f, indent=2)
        print("✅ Results saved to scan_results.json")
    
    print(f"\n🚨 SCAN COMPLETE: Found {len(all_findings)} security issues\n")
    print("="*60)
    
    if all_findings:
        for i, finding in enumerate(all_findings, 1):
            print(f"\n[{i}] {finding['severity']} SEVERITY")
            print(f"📁 File: {finding['file']}")
            print(f"🚨 Issue: {finding['issue']}")
            if 'line' in finding:
                print(f"📝 Line: {finding['line']}")
                print(f"💻 Code: {finding['code']}")
            if 'permissions' in finding:
                print(f"🔒 Permissions: {finding['permissions']}")
                print(f"💡 Recommendation: {finding['recommendation']}")
            print("-" * 60)
    else:
        print("\n✅ No security issues detected!")

if __name__ == "__main__":
    main()
