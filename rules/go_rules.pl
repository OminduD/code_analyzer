# Go Vulnerability & Code Error Detection Rules

[
    # --- VULNERABILITIES ---
    {
        id       => "GO001",
        type     => "vulnerability",
        cwe      => "CWE-78",
        pattern  => qr/\bexec\.Command\s*\(/,
        message  => "Spawning external processes can lead to command injection",
        severity => "HIGH",
        fix      => "Sanitize all arguments to exec.Command",
    },
    {
        id       => "GO002",
        type     => "vulnerability",
        cwe      => "CWE-327",
        pattern  => qr/\bmd5\.New\s*\(\)/,
        message  => "Use of weak cryptographic hash MD5",
        severity => "MEDIUM",
        fix      => "Use crypto/sha256 instead",
    },
    {
        id       => "GO003",
        type     => "vulnerability",
        cwe      => "CWE-79",
        pattern  => qr/\bhtml\/template\b.*(html|js)[A-Z]/,
        message  => "Potentially unsafe template rendering without escaping",
        severity => "HIGH",
        fix      => "Ensure all user input rendered in templates is correctly escaped",
    },
    {
        id       => "GO004",
        type     => "vulnerability",
        cwe      => "CWE-89",
        pattern  => qr/\b(?:Query|QueryRow|Exec)\s*\(\s*(?:fmt\.Sprintf\s*\(\s*["']SELECT|INSERT|UPDATE|DELETE|["']SELECT|INSERT|UPDATE|DELETE.*?["']\s*\+)/i,
        message  => "SQL query built with string formatting or concatenation is vulnerable to SQL Injection",
        severity => "CRITICAL",
        fix      => "Use parameterized queries with placeholders ($1, ?): db.Query('SELECT ... WHERE id = $1', id)",
    },
    {
        id       => "GO005",
        type     => "vulnerability",
        cwe      => "CWE-22",
        pattern  => qr/\b(?:os\.Open|os\.ReadFile|os\.Create|ioutil\.ReadFile)\s*\(\s*(?:req\.|r\.URL|userPath|path|filename)\b/i,
        message  => "Potential Path Traversal when opening files with unvalidated path input",
        severity => "HIGH",
        fix      => "Clean and validate paths using filepath.Clean() and ensure they stay within root directory",
    },
    {
        id       => "GO006",
        type     => "vulnerability",
        cwe      => "CWE-295",
        pattern  => qr/\bInsecureSkipVerify\s*:\s*true\b/,
        message  => "TLS certificate verification disabled (InsecureSkipVerify: true) allows Man-in-the-Middle attacks",
        severity => "HIGH",
        fix      => "Keep InsecureSkipVerify: false and configure RootCAs with trusted certificates",
    },
    {
        id       => "GO007",
        type     => "vulnerability",
        cwe      => "CWE-918",
        pattern  => qr/\bhttp\.(?:Get|Post)\s*\(\s*(?:req|r\.URL|targetURL|userURL)\b/i,
        message  => "Potential Server-Side Request Forgery (SSRF) via untrusted HTTP request target",
        severity => "HIGH",
        fix      => "Validate target URL hostnames against an allowed list before making outbound requests",
    },

    # --- CODE ERRORS & QUALITY BUGS ---
    {
        id       => "GOERR001",
        type     => "error",
        cwe      => "CWE-390",
        pattern  => qr/\b_\s*,\s*err\s*:=.*?;[ \t]*\n[ \t]*\S+(?!.*if\s+err\s*!=)/,
        message  => "Error value ignored or unchecked after function call",
        severity => "MEDIUM",
        fix      => "Check error explicitly: if err != nil { return err }",
    },
    {
        id       => "GOERR002",
        type     => "error",
        cwe      => "CWE-775",
        pattern  => qr/\bhttp\.(?:Get|Post|Head)\s*\(.*?\)(?!.*defer\s+.*Body\.Close\(\))/,
        message  => "HTTP request response body not closed with defer resp.Body.Close() leads to socket leaks",
        severity => "HIGH",
        fix      => "Add defer resp.Body.Close() immediately after checking err == nil",
    },
    {
        id       => "GOERR003",
        type     => "error",
        cwe      => "CWE-369",
        pattern  => qr/[a-zA-Z0-9_\)]\s*[\/%]\s*0(?:\.0*)?(?!\d)/,
        message  => "Division or modulo by literal zero causes runtime panic: runtime error: integer divide by zero",
        severity => "HIGH",
        fix      => "Ensure divisor is non-zero before dividing",
    },

    # --- MALWARE & THREAT RULES ---
    {
        id       => "GO999",
        type     => "malware",
        pattern  => qr/(?i)(Software(?:\\|\/)Microsoft(?:\\|\/)Windows(?:\\|\/)CurrentVersion(?:\\|\/)Run|\.config(?:\\|\/)autostart)/,
        message  => "Potential malware persistence mechanism detected (Windows Run key or Linux autostart)",
        severity => "HIGH",
        fix      => "Remove auto-start functionality unless explicitly required by the application",
    }
]
