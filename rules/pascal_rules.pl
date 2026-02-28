[
    {
        id       => "PASCAL001",
        pattern  => qr/(?i)\bGetMem\s*\(/,
        message  => "Manual memory allocation",
        severity => "LOW",
        fix      => "Ensure matching FreeMem() is called to prevent leaks",
    },
    {
        id       => "PASCAL002",
        pattern  => qr/(?i)Exec\s*\(/,
        message  => "Execution of external programs may lead to command injection",
        severity => "HIGH",
        fix      => "Sanitize executable path and arguments",
    }
]
