[
    {
        id       => 'CSHARP_UNSAFE',
        pattern  => qr/unsafe\s*\{/,
        message  => 'Unsafe code block detected. Ensure memory safety.',
        severity => 'MEDIUM',
        fix      => 'Review the need for unsafe code block.'
    },
    {
        id       => "GEN999",
        pattern  => qr/(?i)(Software(?:\\|\/)Microsoft(?:\\|\/)Windows(?:\\|\/)CurrentVersion(?:\\|\/)Run|\.config(?:\\|\/)autostart)/,
        message  => "Potential malware persistence mechanism detected (Windows Run key or Linux autostart)",
        severity => "HIGH",
        fix      => "Remove auto-start functionality unless explicitly required by the application",
    }
]
