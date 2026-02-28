[
    {
        id       => 'BASH_EVAL',
        pattern  => qr/eval\s+/,
        message  => 'eval command detected. Can execute arbitrary code.',
        severity => 'HIGH',
        fix      => 'Avoid eval; use safer shell constructs.'
    }
];
