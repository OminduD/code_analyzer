[
    {
        id       => 'SWIFT_FORCE_UNWRAP',
        pattern  => qr/!/,
        message  => 'Force unwrap detected. May cause runtime crashes.',
        severity => 'LOW',
        fix      => 'Use safe unwrapping (if let / guard let).'
    }
];
