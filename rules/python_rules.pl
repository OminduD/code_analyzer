[
    {
        id       => "PY001",
        pattern  => qr/\bsubprocess\..*?\(\s*.*shell\s*=\s*True/,
        message  => "subprocess call with shell=True is vulnerable to command injection",
        severity => "HIGH",
        fix      => "Set shell=False and pass arguments as a list",
    },
    {
        id       => "PY002",
        pattern  => qr/\bpickle\.load[s]?\s*\(/,
        message  => "Use of pickle to deserialize data can lead to arbitrary code execution",
        severity => "HIGH",
        fix      => "Use a safer serialization format like JSON",
    },
    {
        id       => "PY003",
        pattern  => qr/\bexec\s*\(/,
        message  => "Use of exec() can lead to arbitrary code execution",
        severity => "HIGH",
        fix      => "Avoid exec() and use safer alternatives",
    },
    {
        id       => "PY004",
        pattern  => qr/(?i)(?:api_key|secret|token)\s*=\s*['"][a-zA-Z0-9_\-]+['"]/,
        message  => "Hardcoded API key or secret detected",
        severity => "HIGH",
        fix      => "Use environment variables or a configuration manager",
    }
]
