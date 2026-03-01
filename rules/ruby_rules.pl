[
    {
        id       => 'RUBY_EVAL',
        pattern  => qr/eval\s*\(/,
        message  => 'Use of eval() detected, which can lead to code injection vulnerabilities.',
        severity => 'HIGH',
        fix      => 'Avoid eval(); use alternative safer methods if possible.'
    },
    {
        id       => "GEN999",
        pattern  => qr/(?i)(Software(?:\\|\/)Microsoft(?:\\|\/)Windows(?:\\|\/)CurrentVersion(?:\\|\/)Run|\.config(?:\\|\/)autostart)/,
        message  => "Potential malware persistence mechanism detected (Windows Run key or Linux autostart)",
        severity => "HIGH",
        fix      => "Remove auto-start functionality unless explicitly required by the application",
    }
]
