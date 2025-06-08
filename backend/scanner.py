import re

def scan_java_code(code):
    findings = []
    lines = code.splitlines()

    for i, line in enumerate(lines, start=1):
        # Cryptographic Vulnerabilities
        if re.search(r'Cipher\.getInstance\(".*DESede.*"\)', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "DESede (Triple DES) used - avoid if possible.",
                "suggestion": "Use AES or stronger encryption algorithms instead of Triple DES.",
                "code_snippet": line.strip()
            })

        if re.search(r'Cipher\.getInstance\(".*DES.*"\)', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "DES used - insecure.",
                "suggestion": "Avoid DES; prefer AES with secure modes like GCM or CBC.",
                "code_snippet": line.strip()
            })

        if re.search(r'MessageDigest\.getInstance\("MD5"\)', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "MD5 is insecure.",
                "suggestion": "Use SHA-256 or stronger hash functions.",
                "code_snippet": line.strip()
            })

        if re.search(r'MessageDigest\.getInstance\("SHA-1"\)', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "SHA-1 is deprecated.",
                "suggestion": "Use SHA-256 or stronger hash algorithms.",
                "code_snippet": line.strip()
            })

        if re.search(r'Cipher\.getInstance\(".*ECB.*"\)', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "ECB mode used - leaks patterns.",
                "suggestion": "Use CBC or GCM modes to prevent pattern leaks.",
                "code_snippet": line.strip()
            })

        if re.search(r'Cipher\.getInstance\(".*PCBC.*"\)', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "PCBC mode used - deprecated.",
                "suggestion": "Avoid PCBC mode; use standard modes like CBC or GCM.",
                "code_snippet": line.strip()
            })

        if re.search(r'new\s+NullCipher\(', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "NullCipher used - no real encryption.",
                "suggestion": "Remove NullCipher usage or replace with actual encryption.",
                "code_snippet": line.strip()
            })

        if re.search(r'String\s+\w+\s*=\s*".{4,}"', line):
            findings.append({
                "line": i,
                "severity": "🔐",
                "description": "Hardcoded key/password found.",
                "suggestion": "Avoid hardcoding keys/passwords; use secure vault or environment variables.",
                "code_snippet": line.strip()
            })

        if re.search(r'SecureRandom\s+\w+\s*=\s*new\s+SecureRandom\(.*\)', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "Predictable SecureRandom seed used.",
                "suggestion": "Ensure SecureRandom is properly seeded with high entropy sources.",
                "code_snippet": line.strip()
            })

        if re.search(r'Signature\.getInstance\(".*SHA1.*"\)', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "Weak digital signature: SHA-1 is deprecated.",
                "suggestion": "Use SHA-256 or stronger algorithms for signatures.",
                "code_snippet": line.strip()
            })

        # SSL/TLS Misconfigurations
        if re.search(r'System\.setProperty\("javax\.net\.debug"', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "Debug mode enabled – disable in production.",
                "suggestion": "Turn off debug mode in production environments to avoid info leaks.",
                "code_snippet": line.strip()
            })

        if re.search(r'HostnameVerifier.*->\s*true', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "HostnameVerifier accepts all hosts – vulnerable to MITM.",
                "suggestion": "Implement strict hostname verification to prevent MITM attacks.",
                "code_snippet": line.strip()
            })

        # Platform Vulnerabilities
        if re.search(r'ObjectInputStream\s*\(', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "Deserialization used – ensure input is trusted.",
                "suggestion": "Avoid deserializing untrusted data to prevent remote code execution.",
                "code_snippet": line.strip()
            })

        if re.search(r'SealedObject\s*\(', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "SealedObject used – validate before deserialization.",
                "suggestion": "Validate objects before deserialization to prevent attacks.",
                "code_snippet": line.strip()
            })

        if re.search(r'ClassLoader\s*\.\s*loadClass\s*\(', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "Custom ClassLoader in use – validate loaded classes.",
                "suggestion": "Ensure only trusted classes are loaded dynamically.",
                "code_snippet": line.strip()
            })

        if re.search(r'System\.setSecurityManager\s*\(\s*null\s*\)', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "SecurityManager disabled – JVM sandbox disabled.",
                "suggestion": "Avoid disabling SecurityManager unless absolutely necessary.",
                "code_snippet": line.strip()
            })

        if re.search(r'AccessController\.doPrivileged\s*\(', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "doPrivileged() used – check for privilege leaks.",
                "suggestion": "Review privileged blocks to avoid privilege escalation.",
                "code_snippet": line.strip()
            })

        if re.search(r'doAs\s*\(', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "JAAS doAs() used – validate authentication config.",
                "suggestion": "Ensure JAAS authentication is securely configured.",
                "code_snippet": line.strip()
            })

        if re.search(r'AllPermission', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "AllPermission used – unrestricted access granted.",
                "suggestion": "Avoid granting AllPermission to untrusted code.",
                "code_snippet": line.strip()
            })

    # Multi-line pattern detection for X509TrustManager
    if re.search(r'X509TrustManager.*checkServerTrusted.*\{[^\}]*\}', code, re.DOTALL):
        findings.append({
            "line": None,
            "severity": "⚠️",
            "description": "X509TrustManager accepts all certs – insecure (multi-line match).",
            "suggestion": "Implement proper certificate validation in X509TrustManager.",
            "code_snippet": ""
        })

    if not findings:
        findings.append({
            "line": None,
            "severity": "✅",
            "description": "No major vulnerabilities found.",
            "suggestion": "",
            "code_snippet": ""
        })

    return findings
