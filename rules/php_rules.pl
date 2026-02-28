[
    {
        id       => "PHP001",
        pattern  => qr/\beval\s*\(/,
        message  => "Use of eval() represents a major security risk",
        severity => "HIGH",
        fix      => "Refactor to avoid eval()",
    },
    {
        id       => "PHP002",
        pattern  => qr/\bquery\s*\(\s*.*?\$_GET/,
        message  => "Direct SQL query with \$_GET detected",
        severity => "HIGH",
        fix      => "Use prepared statements with PDO or MySQLi",
    },
    {
        id       => "PHP003",
        pattern  => qr/\bmysql_query\s*\(/,
        message  => "Deprecated and unsafe mysql_query() usage",
        severity => "HIGH",
        fix      => "Use PDO or MySQLi with prepared statements",
    },
    {
        id       => "PHP004",
        pattern  => qr/\bmd5\s*\(/,
        message  => "Weak hashing algorithm md5() used",
        severity => "MEDIUM",
        fix      => "Use password_hash() instead",
    },
    {
        id       => "PHP005",
        pattern  => qr/\b(exec|shell_exec|system|passthru)\s*\(/,
        message  => "Use of OS execution functions can lead to command injection",
        severity => "HIGH",
        fix      => "Avoid if possible, or use escapeshellarg()/escapeshellcmd()",
    },
    {
        id       => "PHP006",
        pattern  => qr/\bquery\s*\(\s*.*?\$_(POST|REQUEST)/,
        message  => "Direct SQL query with \$_POST or \$_REQUEST detected",
        severity => "HIGH",
        fix      => "Use prepared statements with PDO or MySQLi",
    }
]
