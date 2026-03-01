[
    {
        id       => 'HASKELL_UNSAFE',
        pattern  => qr/unsafePerformIO/,
        message  => 'unsafePerformIO detected. Bypasses type system safety.',
        severity => 'MEDIUM',
        fix      => 'Avoid using unsafePerformIO. Manage side effects explicitly using the IO monad.'
    },
    {
        id       => "GEN999",
        pattern  => qr/(?i)(Software(?:\\|\/)Microsoft(?:\\|\/)Windows(?:\\|\/)CurrentVersion(?:\\|\/)Run|\.config(?:\\|\/)autostart)/,
        message  => "Potential malware persistence mechanism detected (Windows Run key or Linux autostart)",
        severity => "HIGH",
        fix      => "Remove auto-start functionality unless explicitly required by the application",
    }
]
