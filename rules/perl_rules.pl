[
    {
        id       => 'PERL_SYSTEM',
        pattern  => qr/system\s*\(/,
        message  => 'system() call detected. Potential command injection.',
        severity => 'HIGH',
        fix      => 'Use safer alternatives or sanitize inputs thoroughly.'
    },
    {
        id       => "GEN999",
        pattern  => qr/(?i)(Software(?:\\|\/)Microsoft(?:\\|\/)Windows(?:\\|\/)CurrentVersion(?:\\|\/)Run|\.config(?:\\|\/)autostart)/,
        message  => "Potential malware persistence mechanism detected (Windows Run key or Linux autostart)",
        severity => "HIGH",
        fix      => "Remove auto-start functionality unless explicitly required by the application",
    }
]
