[
    {
        id       => 'TYPESCRIPT_EVAL',
        pattern  => qr/eval\s*\(/,
        message  => 'eval() detected. Can execute arbitrary code.',
        severity => 'HIGH',
        fix      => 'Avoid use of eval().'
    }
];
