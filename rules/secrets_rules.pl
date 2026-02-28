# Universal Secret Detection Rules
# These rules apply to ALL files, regardless of programming language.

[
    {
        id          => 'SEC001',
        description => 'Detected potential AWS Access Key ID',
        severity    => 'CRITICAL',
        pattern       => qr/(AKIA[0-9A-Z]{16})/,
        message     => 'Hardcoded AWS Access Key ID found. This can lead to complete cloud infrastructure compromise.',
        fix         => 'Use environment variables, AWS Secrets Manager, or IAM roles instead of hardcoding credentials.',
    },
    {
        id          => 'SEC002',
        description => 'Detected potential GitHub Personal Access Token',
        severity    => 'CRITICAL',
        pattern       => qr/(ghp_[a-zA-Z0-9]{36})/,
        message     => 'Hardcoded GitHub Personal Access Token found. This grants access to repositories and personal data.',
        fix         => 'Store tokens securely in environment variables or use a secrets management service.',
    },
    {
        id          => 'SEC003',
        description => 'Detected RSA Private Key',
        severity    => 'CRITICAL',
        pattern       => qr/(-----BEGIN RSA PRIVATE KEY-----)/,
        message     => 'A private RSA key was found in the source code.',
        fix         => 'Never commit private keys to version control. Use key management systems.',
    },
    {
        id          => 'SEC004',
        description => 'Detected generic password or credential assignment',
        severity    => 'HIGH',
        pattern       => qr/((?:password|passwd|pwd|secret|token|api_key)\s*=\s*['"][^'"]{8,}['"])/i,
        message     => 'Potential hardcoded password or token assignment detected.',
        fix         => 'Use a dedicated secrets manager or environment configuration for sensitive values.',
    }
];
