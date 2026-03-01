[
    {
        id       => 'BASH_EVAL',
        pattern  => qr/eval\s+/,
        message  => 'eval command detected. Can execute arbitrary code.',
        severity => 'HIGH',
        fix      => 'Avoid eval; use safer shell constructs.'
    },
    {
        id       => "GEN999",
        pattern  => qr/(?i)(Software(?:\\|\/)Microsoft(?:\\|\/)Windows(?:\\|\/)CurrentVersion(?:\\|\/)Run|\.config(?:\\|\/)autostart)/,
        message  => "Potential malware persistence mechanism detected (Windows Run key or Linux autostart)",
        severity => "HIGH",
        fix      => "Remove auto-start functionality unless explicitly required by the application",
    }
]
