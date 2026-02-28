[
    {
        id       => 'SCALA_IMPLICIT',
        pattern  => qr/implicit\s+def/,
        message  => 'implicit def detected. Can lead to unpredictable behavior.',
        severity => 'LOW',
        fix      => 'Use explicit conversions or implicit classes where possible.'
    }
];
