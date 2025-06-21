import re

def scan_java_code(code):
    findings = []
    lines = code.splitlines()

    for i, line in enumerate(lines, start=1):
        # --- Weak/Obsolete Algorithms ---
        if re.search(r'Cipher\.getInstance\(".*DESede.*"\)', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "DESede (Triple DES) used - avoid if possible.",
                "suggestion": "Use AES or stronger encryption algorithms instead of Triple DES.",
                "code_snippet": line.strip(),
                "corrected_code": re.sub(r'DESede', 'AES/CBC/PKCS5Padding', line.strip())
            })

        if re.search(r'Cipher\.getInstance\(".*DES.*"\)', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "DES used - insecure.",
                "suggestion": "Avoid DES; prefer AES with secure modes like GCM or CBC.",
                "code_snippet": line.strip(),
                "corrected_code": re.sub(r'DES', 'AES/CBC/PKCS5Padding', line.strip())
            })

        if re.search(r'Cipher\.getInstance\(".*RC4.*"\)', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "RC4 cipher used - known to be insecure.",
                "suggestion": "Avoid RC4; use AES with a secure mode instead.",
                "code_snippet": line.strip(),
                "corrected_code": re.sub(r'RC4', 'AES/CBC/PKCS5Padding', line.strip())
            })

        if re.search(r'Cipher\.getInstance\(".*RC2.*"\)', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "RC2 cipher is outdated and weak.",
                "suggestion": "Use AES instead of RC2.",
                "code_snippet": line.strip(),
                "corrected_code": re.sub(r'RC2', 'AES/CBC/PKCS5Padding', line.strip())
            })

        if re.search(r'Cipher\.getInstance\(".*ECB.*"\)', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "ECB mode used - leaks patterns.",
                "suggestion": "Use CBC or GCM modes to prevent pattern leaks.",
                "code_snippet": line.strip(),
                "corrected_code": re.sub(r'ECB', 'CBC', line.strip())
            })

        if re.search(r'Cipher\.getInstance\(".*PCBC.*"\)', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "PCBC mode used - deprecated.",
                "suggestion": "Avoid PCBC mode; use standard modes like CBC or GCM.",
                "code_snippet": line.strip(),
                "corrected_code": re.sub(r'PCBC', 'CBC', line.strip())
            })

        # --- Weak Padding ---
        if re.search(r'Cipher\.getInstance\(".*NoPadding.*"\)', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "NoPadding used - insecure if not handled manually.",
                "suggestion": "Use PKCS5Padding or GCM.",
                "code_snippet": line.strip(),
                "corrected_code": re.sub(r'NoPadding', 'PKCS5Padding', line.strip())
            })

        if re.search(r'Cipher\.getInstance\(".*PKCS1Padding.*"\)', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "PKCS1Padding is outdated for RSA encryption.",
                "suggestion": "Use OAEP (Optimal Asymmetric Encryption Padding) instead.",
                "code_snippet": line.strip(),
                "corrected_code": re.sub(r'PKCS1Padding', 'OAEPWithSHA-256AndMGF1Padding', line.strip())
            })

        # --- Digest & Signature ---
        if re.search(r'MessageDigest\.getInstance\("MD5"\)', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "MD5 is insecure.",
                "suggestion": "Use SHA-256 or stronger hash functions.",
                "code_snippet": line.strip(),
                "corrected_code": re.sub(r'MD5', 'SHA-256', line.strip())
            })

        if re.search(r'MessageDigest\.getInstance\("SHA-1"\)', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "SHA-1 is deprecated.",
                "suggestion": "Use SHA-256 or stronger hash algorithms.",
                "code_snippet": line.strip(),
                "corrected_code": re.sub(r'SHA-1', 'SHA-256', line.strip())
            })

        if re.search(r'Signature\.getInstance\(".*SHA1.*"\)', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "Weak digital signature: SHA-1 is deprecated.",
                "suggestion": "Use SHA-256 or stronger algorithms for signatures.",
                "code_snippet": line.strip(),
                "corrected_code": re.sub(r'SHA1', 'SHA256', line.strip())
            })

        # --- Key & IV Misuse ---
        if re.search(r'IvParameterSpec\(\s*new\s+byte\[\d+\]\s*\)', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "Static IV (zero or constant) detected.",
                "suggestion": "Use random, unique IVs for each encryption operation.",
                "code_snippet": line.strip(),
                "corrected_code": '// Use SecureRandom to generate IV\nbyte[] iv = new byte[16]; new SecureRandom().nextBytes(iv); IvParameterSpec ivSpec = new IvParameterSpec(iv);'
            })

        if re.search(r'SecretKeySpec\(\s*".*".getBytes\(\)', line):
            findings.append({
                "line": i,
                "severity": "🔐",
                "description": "Hardcoded key detected in SecretKeySpec.",
                "suggestion": "Load keys from a secure keystore or env variable.",
                "code_snippet": line.strip(),
                "corrected_code": '// Load key from secure env\nSecretKeySpec key = new SecretKeySpec(System.getenv("KEY").getBytes(), "AES");'
            })

        if re.search(r'SecureRandom\.getInstance\("SHA1PRNG"\)', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "SHA1PRNG is weak and predictable.",
                "suggestion": "Use default SecureRandom constructor or NativePRNG.",
                "code_snippet": line.strip(),
                "corrected_code": 'new SecureRandom()'
            })

        if re.search(r'SecureRandom\s+\w+\s*=\s*new\s+SecureRandom\(.*\)', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "Potentially predictable SecureRandom seed used.",
                "suggestion": "Ensure SecureRandom is properly seeded with high entropy sources.",
                "code_snippet": line.strip(),
                "corrected_code": 'SecureRandom sr = new SecureRandom();'
            })

        # --- Crypto API Misuse ---
        if re.search(r'Base64\.encode', line) or re.search(r'sun\.misc\.BASE64Encoder', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "Using non-standard Base64 encoder.",
                "suggestion": "Use java.util.Base64 for compatibility and security.",
                "code_snippet": line.strip(),
                "corrected_code": 'Base64.getEncoder().encode(...)'
            })

        if re.search(r'Cipher\.getInstance\("AES"\)', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "AES without mode/padding defaults to ECB.",
                "suggestion": "Specify AES mode and padding explicitly (e.g., AES/CBC/PKCS5Padding).",
                "code_snippet": line.strip(),
                "corrected_code": 'Cipher.getInstance("AES/CBC/PKCS5Padding")'
            })

        if re.search(r'new\s+NullCipher\(', line):
            findings.append({
                "line": i,
                "severity": "⚠️",
                "description": "NullCipher used - no real encryption.",
                "suggestion": "Remove NullCipher usage or replace with actual encryption.",
                "code_snippet": line.strip(),
                "corrected_code": 'Cipher.getInstance("AES/CBC/PKCS5Padding")'
            })

        if re.search(r'String\s+\w+\s*=\s*".{4,}"', line):
            findings.append({
                "line": i,
                "severity": "🔐",
                "description": "Hardcoded key/password found.",
                "suggestion": "Avoid hardcoding keys/passwords; use secure vault or environment variables.",
                "code_snippet": line.strip(),
                "corrected_code": '// Use secure environment variable\nString password = System.getenv("PASSWORD");'
            })

    # --- Final catch-all ---
    if not findings:
        findings.append({
            "line": None,
            "severity": "✅",
            "description": "No major vulnerabilities found.",
            "suggestion": "",
            "code_snippet": "",
            "corrected_code": ""
        })

    return findings
