[
    {
        id       => "GO001",
        pattern  => qr/\bexec\.Command\s*\(/,
        message  => "Spawning external processes can lead to command injection",
        severity => "HIGH",
        fix      => "Sanitize all arguments to exec.Command",
    },
    {
        id       => "GO002",
        pattern  => qr/\bmd5\.New\s*\(\)/,
        message  => "Use of weak cryptographic hash MD5",
        severity => "MEDIUM",
        fix      => "Use crypto/sha256 instead",
    },
    {
        id       => "GO003",
        pattern  => qr/\bhtml\/template\b.*(html|js)[A-Z]/,
        message  => "Potentially unsafe template rendering without escaping",
        severity => "HIGH",
        fix      => "Ensure all user input rendered in templates is correctly escaped",
    }
]
