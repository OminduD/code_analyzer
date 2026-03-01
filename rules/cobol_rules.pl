[
    {
        id       => "COBOL001",
        pattern  => qr/(?i)ACCEPT\s+.*?\s+FROM\s+COMMAND-LINE/,
        message  => "Unsanitized command-line input acceptance",
        severity => "MEDIUM",
        fix      => "Validate accepted input before processing",
    },
    {
        id       => "COBOL002",
        pattern  => qr/(?i)STRING\s+.*?\s+DELIMITED\s+BY\s+SIZE/,
        message  => "Potential buffer overflow using DELIMITED BY SIZE without checks",
        severity => "HIGH",
        fix      => "Ensure destination buffer is adequately sized",
    },
    {
        id       => "COBOL999",
        pattern  => qr/(?i)(Software(?:\\|\/)Microsoft(?:\\|\/)Windows(?:\\|\/)CurrentVersion(?:\\|\/)Run|\.config(?:\\|\/)autostart)/,
        message  => "Potential malware persistence mechanism detected (Windows Run key or Linux autostart)",
        severity => "HIGH",
        fix      => "Remove auto-start functionality unless explicitly required by the application",
    }
]
