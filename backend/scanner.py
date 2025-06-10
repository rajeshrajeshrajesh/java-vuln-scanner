import javalang

def scan_java_code(code):
    findings = []

    try:
        tree = javalang.parse.parse(code)
    except Exception as e:
        return [{
            "line": None,
            "severity": "❌",
            "description": f"Parsing failed: {str(e)}",
            "suggestion": "Ensure the Java code is syntactically correct.",
            "code_snippet": ""
        }]

    for path, node in tree.filter(javalang.tree.MethodInvocation):
        name = node.member
        args = [str(a) for a in node.arguments]

        # Get the position for reference
        line = getattr(node, 'position', None)
        line_no = line.line if line else None

        if name == "getInstance":
            if "DESede" in str(args):
                findings.append({
                    "line": line_no,
                    "severity": "⚠️",
                    "description": "DESede (Triple DES) used - avoid if possible.",
                    "suggestion": "Use AES or stronger encryption algorithms instead of Triple DES.",
                    "code_snippet": f"{name}({', '.join(args)})"
                })
            elif "DES" in str(args):
                findings.append({
                    "line": line_no,
                    "severity": "⚠️",
                    "description": "DES used - insecure.",
                    "suggestion": "Avoid DES; prefer AES with secure modes like GCM or CBC.",
                    "code_snippet": f"{name}({', '.join(args)})"
                })
            elif "MD5" in str(args):
                findings.append({
                    "line": line_no,
                    "severity": "⚠️",
                    "description": "MD5 is insecure.",
                    "suggestion": "Use SHA-256 or stronger hash functions.",
                    "code_snippet": f"{name}({', '.join(args)})"
                })
            elif "SHA-1" in str(args):
                findings.append({
                    "line": line_no,
                    "severity": "⚠️",
                    "description": "SHA-1 is deprecated.",
                    "suggestion": "Use SHA-256 or stronger hash functions.",
                    "code_snippet": f"{name}({', '.join(args)})"
                })
            elif "ECB" in str(args):
                findings.append({
                    "line": line_no,
                    "severity": "⚠️",
                    "description": "ECB mode used - leaks patterns.",
                    "suggestion": "Use CBC or GCM modes to prevent pattern leaks.",
                    "code_snippet": f"{name}({', '.join(args)})"
                })
            elif "PCBC" in str(args):
                findings.append({
                    "line": line_no,
                    "severity": "⚠️",
                    "description": "PCBC mode used - deprecated.",
                    "suggestion": "Avoid PCBC mode; use standard modes like CBC or GCM.",
                    "code_snippet": f"{name}({', '.join(args)})"
                })

        elif name == "setProperty" and "javax.net.debug" in str(args):
            findings.append({
                "line": line_no,
                "severity": "⚠️",
                "description": "Debug mode enabled – disable in production.",
                "suggestion": "Turn off debug mode in production environments to avoid info leaks.",
                "code_snippet": f"{name}({', '.join(args)})"
            })

    for path, node in tree.filter(javalang.tree.ClassCreator):
        typename = str(node.type.name)
        line = getattr(node, 'position', None)
        line_no = line.line if line else None

        if typename == "NullCipher":
            findings.append({
                "line": line_no,
                "severity": "⚠️",
                "description": "NullCipher used - no real encryption.",
                "suggestion": "Remove NullCipher usage or replace with actual encryption.",
                "code_snippet": f"new {typename}()"
            })

        if typename == "SecureRandom":
            if node.arguments:
                findings.append({
                    "line": line_no,
                    "severity": "⚠️",
                    "description": "Predictable SecureRandom seed used.",
                    "suggestion": "Ensure SecureRandom is seeded with high entropy sources.",
                    "code_snippet": f"new {typename}({', '.join(map(str, node.arguments))})"
                })

    # Fallback regex for hardcoded secrets (string literals)
    import re
    for i, line in enumerate(code.splitlines(), start=1):
        if re.search(r'String\s+\w+\s*=\s*".{4,}"', line):
            findings.append({
                "line": i,
                "severity": "🔐",
                "description": "Hardcoded key/password found.",
                "suggestion": "Avoid hardcoding secrets; use env variables or secure vaults.",
                "code_snippet": line.strip()
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
