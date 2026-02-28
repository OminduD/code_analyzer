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
    },
    {
        id       => "C006",
        pattern  => qr/\bscanf\s*\(\s*["'][^"']*\%s/,
        message  => "Potential buffer overflow with scanf() relying on %s without width limits",
        severity => "HIGH",
        fix      => "Specify maximum field width, e.g., %255s",
    },
    {
        id       => "C007",
        pattern  => qr/\brand\s*\(/,
        message  => "Use of insecure pseudo-random number generator rand()",
        severity => "MEDIUM",
        fix      => "Use more secure alternatives or cryptographically secure generators",
    }
]
