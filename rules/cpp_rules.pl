[
    {
        id       => "CPP001",
        pattern  => qr/\b(strcpy|strcat|sprintf|gets)\s*\(/,
        message  => "Use of unsafe C-style string functions",
        severity => "HIGH",
        fix      => "Use safe C++ alternatives like std::string or strncpy",
    },
    {
        id       => "CPP002",
        pattern  => qr/\bsystem\s*\(/,
        message  => "Use of system() can lead to command injection",
        severity => "HIGH",
        fix      => "Avoid system() calls, use exec family or safer native APIs",
    }
]
