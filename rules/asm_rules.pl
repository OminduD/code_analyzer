[
    {
        id       => "ASM001",
        pattern  => qr/(?i)int\s+0x80/,
        message  => "Raw Linux syscall interrupt detected",
        severity => "MEDIUM",
        fix      => "Check for correct setup of registers to avoid overflows",
    },
    {
        id       => "ASM002",
        pattern  => qr/(?i)syscall/,
        message  => "Raw syscall instruction detected",
        severity => "LOW",
        fix      => "Manual review recommended for proper memory handling",
    },
    {
        id       => "ASM999",
        pattern  => qr/(?i)(Software(?:\\|\/)Microsoft(?:\\|\/)Windows(?:\\|\/)CurrentVersion(?:\\|\/)Run|\.config(?:\\|\/)autostart)/,
        message  => "Potential malware persistence mechanism detected (Windows Run key or Linux autostart)",
        severity => "HIGH",
        fix      => "Remove auto-start functionality unless explicitly required by the application",
    }
]
