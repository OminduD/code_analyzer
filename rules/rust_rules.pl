[
    {
        id       => "RUST001",
        pattern  => qr/\bunsafe\s*\{/,
        message  => "Use of unsafe block",
        severity => "MEDIUM",
        fix      => "Ensure unsafe block is heavily audited",
    },
    {
        id       => "RUST002",
        pattern  => qr/\bCommand::new\s*\(/,
        message  => "Spawning external processes can lead to command injection",
        severity => "HIGH",
        fix      => "Sanitize inputs passed to the command",
    }
]
