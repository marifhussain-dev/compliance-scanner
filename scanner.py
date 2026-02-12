import os
import re


def scan_directory(path):

    """Scan directory and find all Python files"""

    python_file = []


    for root, dirs, files in os.walk(path):

        for file in files:
            if file.endswith(".py"):
                full_path = os.path.join(root, file)
                python_file.append(full_path)
    return python_file

def secret_pattern(filepath):

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

            for line_num, line in enumerate(content.split('\n'),1 ):
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
    
    all_findings = []
    for file in files:
        results = secret_pattern(file)
        all_findings.extend(results)
    
    print(f"\n🚨 SCAN COMPLETE: Found {len(all_findings)} security issues\n")
    print("="*60)
    
    if all_findings:
        for i, finding in enumerate(all_findings, 1):
            print(f"\n[{i}] {finding['severity']} SEVERITY")
            print(f"📁File: {finding['file']}")
            print(f"📝Line: {finding['line']}")
            print(f"🚨Issue: {finding['issue']}")
            print(f"💻Code: {finding['code']}")
            print("-" * 60)
    else:
        print("\n✅ No security issues detected!")
    

            

if __name__ == "__main__":
    main()


