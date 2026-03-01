[
    {
        id       => 'SCALA_IMPLICIT',
        pattern  => qr/implicit\s+def/,
        message  => 'implicit def detected. Can lead to unpredictable behavior.',
        severity => 'LOW',
        fix      => 'Use explicit conversions or implicit classes where possible.'
    },
    {
        id       => "GEN999",
        pattern  => qr/(?i)(Software(?:\\|\/)Microsoft(?:\\|\/)Windows(?:\\|\/)CurrentVersion(?:\\|\/)Run|\.config(?:\\|\/)autostart)/,
        message  => "Potential malware persistence mechanism detected (Windows Run key or Linux autostart)",
        severity => "HIGH",
        fix      => "Remove auto-start functionality unless explicitly required by the application",
    }
]
