[
    {
        id       => 'TYPESCRIPT_EVAL',
        pattern  => qr/eval\s*\(/,
        message  => 'eval() detected. Can execute arbitrary code.',
        severity => 'HIGH',
        fix      => 'Avoid use of eval().'
    },
    {
        id       => "GEN999",
        pattern  => qr/(?i)(Software(?:\\|\/)Microsoft(?:\\|\/)Windows(?:\\|\/)CurrentVersion(?:\\|\/)Run|\.config(?:\\|\/)autostart)/,
        message  => "Potential malware persistence mechanism detected (Windows Run key or Linux autostart)",
        severity => "HIGH",
        fix      => "Remove auto-start functionality unless explicitly required by the application",
    }
]
