[
    {
        id       => 'SWIFT_FORCE_UNWRAP',
        pattern  => qr/!/,
        message  => 'Force unwrap detected. May cause runtime crashes.',
        severity => 'LOW',
        fix      => 'Use safe unwrapping (if let / guard let).'
    },
    {
        id       => "GEN999",
        pattern  => qr/(?i)(Software(?:\\|\/)Microsoft(?:\\|\/)Windows(?:\\|\/)CurrentVersion(?:\\|\/)Run|\.config(?:\\|\/)autostart)/,
        message  => "Potential malware persistence mechanism detected (Windows Run key or Linux autostart)",
        severity => "HIGH",
        fix      => "Remove auto-start functionality unless explicitly required by the application",
    }
]
