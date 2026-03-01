[
    {
        id       => 'KOTLIN_EVAL',
        pattern  => qr/ScriptEngineManager/,
        message  => 'Script engine usage detected. Potential for injection.',
        severity => 'HIGH',
        fix      => 'Avoid evaluating arbitrary scripts.'
    },
    {
        id       => "GEN999",
        pattern  => qr/(?i)(Software(?:\\|\/)Microsoft(?:\\|\/)Windows(?:\\|\/)CurrentVersion(?:\\|\/)Run|\.config(?:\\|\/)autostart)/,
        message  => "Potential malware persistence mechanism detected (Windows Run key or Linux autostart)",
        severity => "HIGH",
        fix      => "Remove auto-start functionality unless explicitly required by the application",
    }
]
