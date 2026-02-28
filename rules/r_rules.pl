[
    {
        id       => 'R_SYSTEM',
        pattern  => qr/system\s*\(/,
        message  => 'system() call detected. Potential command injection.',
        severity => 'HIGH',
        fix      => 'Use safer alternatives or sanitize inputs thoroughly.'
    }
];
