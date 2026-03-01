[
    {
        id       => 'CSHARP_UNSAFE',
        pattern  => qr/unsafe\s*\{/,
        message  => 'Unsafe code block detected. Ensure memory safety.',
        severity => 'MEDIUM',
        fix      => 'Review the need for unsafe code block.'
    },
    {
        id       => "CS002",
        pattern  => qr/\bRegistry(?:Key)?\.[a-zA-Z0-9_]+\.OpenSubKey\s*\(/,
        message  => "Potential Windows Registry access. Ensure access is intended and does not lead to information disclosure.",
        severity => "MEDIUM",
        fix      => "Review registry access to ensure safe and authorized keys are read.",
    },
    {
        id       => "CS003",
        pattern  => qr/\bRegistry(?:Key)?\.[a-zA-Z0-9_]+\.(?:CreateSubKey|SetValue|DeleteSubKey|DeleteSubKeyTree|DeleteValue)\s*\(/,
        message  => "Potential Windows Registry modification. Ensure modification is intended and not creating unwanted keys or malware persistence.",
        severity => "HIGH",
        fix      => "Avoid modifying the registry unless strictly necessary, and validate all keys and values.",
    },
    {
        id       => "CS004",
        pattern  => qr/\b(?:new\s+Socket\s*\(\s*AddressFamily\.[a-zA-Z0-9_]+\s*,\s*SocketType\.Raw|SharpPcap|PcapDeviceList\.Instance)/,
        message  => "Potential covert network communication or packet sniffing detected. Use of raw sockets or packet capture libraries indicates low-level network access.",
        severity => "HIGH",
        fix      => "Review network access requirements and ensure they are explicitly needed for the application's functionality.",
    },
    {
        id       => "GEN999",
        pattern  => qr/(?i)(Software(?:\\|\/)Microsoft(?:\\|\/)Windows(?:\\|\/)CurrentVersion(?:\\|\/)Run|\.config(?:\\|\/)autostart)/,
        message  => "Potential malware persistence mechanism detected (Windows Run key or Linux autostart)",
        severity => "HIGH",
        fix      => "Remove auto-start functionality unless explicitly required by the application",
    }
]
