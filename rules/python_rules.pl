# Python Vulnerability & Code Error Detection Rules

[
    # --- VULNERABILITIES ---
    {
        id       => "PY001",
        type     => "vulnerability",
        cwe      => "CWE-78",
        pattern  => qr/\bsubprocess\..*?\(\s*.*shell\s*=\s*True/,
        message  => "subprocess call with shell=True is vulnerable to command injection",
        severity => "HIGH",
        fix      => "Set shell=False and pass arguments as a list",
    },
    {
        id       => "PY002",
        type     => "vulnerability",
        cwe      => "CWE-502",
        pattern  => qr/\bpickle\.load[s]?\s*\(/,
        message  => "Use of pickle to deserialize data can lead to arbitrary code execution",
        severity => "HIGH",
        fix      => "Use a safer serialization format like JSON",
    },
    {
        id       => "PY003",
        type     => "vulnerability",
        cwe      => "CWE-95",
        pattern  => qr/\bexec\s*\(/,
        message  => "Use of exec() can lead to arbitrary code execution",
        severity => "HIGH",
        fix      => "Avoid exec() and use safer alternatives",
    },
    {
        id       => "PY004",
        type     => "secret",
        cwe      => "CWE-798",
        pattern  => qr/(?i)(?:api_key|secret|token)\s*=\s*['"][a-zA-Z0-9_\-]{16,}['"]/,
        message  => "Hardcoded API key or secret detected",
        severity => "HIGH",
        fix      => "Use environment variables or a configuration manager",
    },
    {
        id       => "PY005",
        type     => "vulnerability",
        cwe      => "CWE-502",
        pattern  => qr/\byaml\.load\s*\(/,
        message  => "Unsafe YAML deserialization",
        severity => "HIGH",
        fix      => "Use yaml.safe_load() instead of yaml.load()",
    },
    {
        id       => "PY006",
        type     => "vulnerability",
        cwe      => "CWE-327",
        pattern  => qr/\bhashlib\.(md5|sha1)\s*\(/,
        message  => "Use of weak cryptographic hash function (MD5 or SHA1)",
        severity => "MEDIUM",
        fix      => "Use stronger hashing algorithms like SHA-256",
    },
    {
        id       => "PY007",
        type     => "error",
        cwe      => "CWE-835",
        pattern  => qr/\bwhile\s+True\s*:/,
        message  => "Potential infinite loop detected (while True without apparent exit condition)",
        severity => "MEDIUM",
        fix      => "Ensure the loop has a clear exit condition or break statement",
    },
    {
        # Advanced Recursion Detection
        id         => "PY008",
        type       => "error",
        cwe        => "CWE-674",
        match_func => sub {
            my ($file, $token, $vulnerabilities) = @_;
            our $current_func;
            our %last_file;
            our $func_indent = 0;
            our $has_base_case = 0;

            if (!$last_file{py_rec} || $last_file{py_rec} ne $file) {
                $current_func = "";
                $has_base_case = 0;
                $last_file{py_rec} = $file;
            }

            my $content = $token->{content};
            my $line    = $token->{line_num};

            # Detect function definition: def my_func(args):
            if ($content =~ /^(\s*)def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/) {
                $func_indent = length($1);
                $current_func = $2;
                $has_base_case = 0;
                return undef;
            }

            # If we are inside a function
            if ($current_func) {
                if ($content =~ /^(\s*)\S/ && length($1) <= $func_indent && $content !~ /^\s*def\s+/) {
                    $current_func = "";
                    $has_base_case = 0;
                    return undef;
                }
                
                if ($content =~ /^\s*(?:if|elif)\b/) {
                    $has_base_case = 1;
                }

                if ($content =~ /\b$current_func\s*\(/) {
                    if (!$has_base_case) {
                        return {
                            file     => $file,
                            line     => $line,
                            rule_id  => "PY008",
                            message  => "Uncontrolled Recursion (Stack Overflow): '$current_func' calls itself without a prior conditional base-case.",
                            severity => "CRITICAL",
                            fix      => "Ensure the recursion has a proper conditional base case (if) to avoid RecursionError.",
                            snippet  => $content,
                        };
                    }
                }
            }
            return undef;
        }
    },
    {
        id       => "PY009",
        type     => "vulnerability",
        cwe      => "CWE-89",
        pattern  => qr/(?:execute|cursor\.execute)\s*\(\s*(?:f["'].*?SELECT|INSERT|UPDATE|DELETE|["'].*?SELECT|INSERT|UPDATE|DELETE.*?["']\s*\%|["'].*?SELECT|INSERT|UPDATE|DELETE.*?\.format\s*\()/i,
        message  => "SQL query built with string formatting / f-string is vulnerable to SQL Injection",
        severity => "CRITICAL",
        fix      => "Use parameterized queries with DB-API placeholders (%s or ?): cursor.execute('SELECT ... WHERE id = %s', (val,))",
    },
    {
        id       => "PY010",
        type     => "vulnerability",
        cwe      => "CWE-918",
        pattern  => qr/\b(?:requests\.(?:get|post|put|delete)|urllib\.request\.urlopen|httpx\.(?:get|post))\s*\(\s*(?:request\.|req\.|url|target|user_url)/i,
        message  => "Potential Server-Side Request Forgery (SSRF) via unvalidated outbound HTTP request",
        severity => "HIGH",
        fix      => "Validate outbound URLs against a strict domain whitelist and reject private IP ranges (127.0.0.1, 169.254.169.254)",
    },
    {
        id       => "PY011",
        type     => "vulnerability",
        cwe      => "CWE-22",
        pattern  => qr/\bopen\s*\(\s*(?:os\.path\.join\s*\([^,]+,\s*(?:req|request|user|filename|path)\b|(?:req|request|filename)\b)/i,
        message  => "Potential Path Traversal vulnerability when opening files from untrusted input",
        severity => "HIGH",
        fix      => "Sanitize file path with os.path.basename() and verify with os.path.abspath(target).startswith(safe_dir)",
    },
    {
        id       => "PY012",
        type     => "vulnerability",
        cwe      => "CWE-611",
        pattern  => qr/\b(?:xml\.etree\.ElementTree\.(?:parse|fromstring)|xml\.dom\.minidom\.parse(?:String)?|xml\.sax\.parse)\s*\(/,
        message  => "Standard Python XML parsers are vulnerable to XML External Entity (XXE) and entity expansion attacks",
        severity => "HIGH",
        fix      => "Use defusedxml package instead of standard xml modules to prevent XXE attacks",
    },
    {
        id       => "PY013",
        type     => "vulnerability",
        cwe      => "CWE-295",
        pattern  => qr/\b(?:verify\s*=\s*False|check_hostname\s*=\s*False)/,
        message  => "Disabling TLS certificate verification (verify=False) enables Man-in-the-Middle (MitM) attacks",
        severity => "HIGH",
        fix      => "Keep TLS verification enabled (verify=True) and provide trusted CA bundle if needed",
    },
    {
        id       => "PY014",
        type     => "vulnerability",
        cwe      => "CWE-489",
        pattern  => qr/(?:\.run\s*\(.*?debug\s*=\s*True|DEBUG\s*=\s*True)/,
        message  => "Debug mode enabled in production exposes interactive debuggers and sensitive system internals",
        severity => "HIGH",
        fix      => "Ensure debug=False in production environments",
    },
    {
        id       => "PY015",
        type     => "vulnerability",
        cwe      => "CWE-377",
        pattern  => qr/\btempfile\.mktemp\s*\(/,
        message  => "tempfile.mktemp() is deprecated and vulnerable to race condition file replacement",
        severity => "MEDIUM",
        fix      => "Use tempfile.NamedTemporaryFile() or tempfile.mkstemp() instead",
    },

    # --- CODE ERRORS & QUALITY BUGS ---
    {
        id       => "PYERR001",
        type     => "error",
        cwe      => "CWE-390",
        pattern  => qr/\bexcept(?:\s+Exception)?\s*:\s*pass\b/,
        message  => "Empty except statement swallows exceptions silently without logging or error recovery",
        severity => "MEDIUM",
        fix      => "Catch specific exception types and log the error message using the logging module",
    },
    {
        id       => "PYERR002",
        type     => "error",
        cwe      => "CWE-665",
        pattern  => qr/\bdef\s+[a-zA-Z0-9_]+\s*\([^)]*?=\s*(?:\[\]|\{\})\s*[,)]/,
        message  => "Mutable default argument ([] or {}) in function definition creates persistent state across calls",
        severity => "HIGH",
        fix      => "Use default value None and initialize the mutable structure inside the function body (if arg is None: arg = [])",
    },
    {
        id       => "PYERR003",
        type     => "error",
        cwe      => "CWE-369",
        pattern  => qr/[a-zA-Z0-9_\)]\s*[\/%]\s*0(?:\.0*)?(?!\d)/,
        message  => "Division or modulo by literal zero raises ZeroDivisionError",
        severity => "HIGH",
        fix      => "Verify denominator is non-zero before dividing",
    },
    {
        id       => "PYERR004",
        type     => "error",
        cwe      => "CWE-1025",
        pattern  => qr/[a-zA-Z0-9_]\s*(?:==|!=)\s*None\b/,
        message  => "Comparing against None using '==' or '!=' rather than identity check 'is None'",
        severity => "LOW",
        fix      => "Use 'is None' or 'is not None' for None comparisons",
    },
    {
        id       => "PYERR005",
        type     => "error",
        cwe      => "CWE-561",
        pattern  => qr/^\s*(?:return|raise)\b.*?\n\s{4,}[a-zA-Z0-9_]/,
        message  => "Dead code detected immediately following return or raise statement",
        severity => "LOW",
        fix      => "Remove unreachable statements following return or raise",
    },

    # --- MALWARE & THREAT RULES ---
    {
        id       => "PY_MAL001",
        type     => "malware",
        pattern  => qr/\bexec\s*\(\s*(?:base64\.b64decode|zlib\.decompress|codecs\.decode|bytes\.fromhex)\s*\(/,
        message  => "Obfuscated code execution: exec() called with decoded/decompressed data. Malware signature.",
        severity => "CRITICAL",
        fix      => "Remove obfuscated exec patterns. All executed code should be readable source code.",
    },
    {
        id       => "PY_MAL002",
        type     => "malware",
        pattern  => qr/\bctypes\b.*?\b(?:VirtualAlloc|VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|OpenProcess)\b/s,
        message  => "Process injection via ctypes memory manipulation APIs detected.",
        severity => "CRITICAL",
        fix      => "Remove process memory injection code.",
    },
    {
        id       => "PY_MAL003",
        type     => "malware",
        pattern  => qr/\bsocket\.connect\s*\(.*?\).*?(?:subprocess|os\.dup2|os\.execv)/s,
        message  => "Potential reverse shell: socket connection combined with process I/O redirection.",
        severity => "CRITICAL",
        fix      => "Remove reverse shell code immediately.",
    },
    {
        id       => "PY_MAL004",
        type     => "malware",
        pattern  => qr/(?i)(?:stratum\+tcp:\/\/|xmrig|minerd|cpuminer|cryptonight|monero.*?wallet)/,
        message  => "Potential cryptocurrency miner: references to mining protocols or binaries detected.",
        severity => "CRITICAL",
        fix      => "Remove cryptocurrency mining code.",
    },
    {
        id       => "PY_MAL005",
        type     => "malware",
        pattern  => qr/\bos\.fork\s*\(\s*\)/,
        message  => "os.fork() detected. Can cause exponential process exhaustion / fork bomb.",
        severity => "HIGH",
        fix      => "Use multiprocessing.Pool with bounded worker count instead of os.fork().",
    },
    {
        id       => "PY_MAL006",
        type     => "malware",
        pattern  => qr/\b(?:os\.setsid\s*\(\s*\)|subprocess\.Popen.*?start_new_session\s*=\s*True)/,
        message  => "Detached background process launched. Malware hides by detaching from controlling terminal.",
        severity => "HIGH",
        fix      => "Use standard system services for legitimate background workers.",
    },
    {
        id       => "PY999",
        type     => "malware",
        pattern  => qr/(?i)(Software(?:\\|\/)Microsoft(?:\\|\/)Windows(?:\\|\/)CurrentVersion(?:\\|\/)Run|\.config(?:\\|\/)autostart)/,
        message  => "Potential malware persistence mechanism detected (Windows Run key or Linux autostart)",
        severity => "HIGH",
        fix      => "Remove auto-start functionality unless explicitly required by the application",
    }
]
