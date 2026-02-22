[
    {
        id       => "C001",
        pattern  => qr/\bgets\s*\(/,
        message  => "Use of unsafe function gets()",
        severity => "HIGH",
        fix      => "Use fgets() instead",
    },
    {
        id       => "C002",
        pattern  => qr/\bstrcpy\s*\(/,
        message  => "Use of unsafe function strcpy()",
        severity => "HIGH",
        fix      => "Use strncpy() instead",
    },
    {
        id       => "C003",
        pattern  => qr/\bsprintf\s*\(/,
        message  => "Potential buffer overflow with sprintf()",
        severity => "MEDIUM",
        fix      => "Use snprintf() instead",
    },
    {
        id       => "C004",
        pattern  => qr/\bsystem\s*\(/,
        message  => "Use of system() can lead to command injection",
        severity => "HIGH",
        fix      => "Use exec() family functions instead",
    },
    {
        id       => "C005",
        pattern  => qr/(?i)password\s*=\s*["'][^"']+["']/,
        message  => "Hardcoded password detected",
        severity => "HIGH",
        fix      => "Use environment variables or secure vault",
    }
]
