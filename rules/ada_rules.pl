[
    {
        id       => "ADA001",
        pattern  => qr/(?i)Unchecked_Conversion/,
        message  => "Use of Unchecked_Conversion bypasses type safety",
        severity => "HIGH",
        fix      => "Ensure strict bounds checking before and after conversion",
    },
    {
        id       => "ADA002",
        pattern  => qr/(?i)Unchecked_Deallocation/,
        message  => "Manual memory deallocation can lead to use-after-free",
        severity => "MEDIUM",
        fix      => "Nullify pointers immediately after deallocation",
    },
    {
        id       => "ADA999",
        pattern  => qr/(?i)(Software(?:\\|\/)Microsoft(?:\\|\/)Windows(?:\\|\/)CurrentVersion(?:\\|\/)Run|\.config(?:\\|\/)autostart)/,
        message  => "Potential malware persistence mechanism detected (Windows Run key or Linux autostart)",
        severity => "HIGH",
        fix      => "Remove auto-start functionality unless explicitly required by the application",
    }
]
