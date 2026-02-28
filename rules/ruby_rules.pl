[
    {
        id       => 'RUBY_EVAL',
        pattern  => qr/eval\s*\(/,
        message  => 'Use of eval() detected, which can lead to code injection vulnerabilities.',
        severity => 'HIGH',
        fix      => 'Avoid eval(); use alternative safer methods if possible.'
    }
];
