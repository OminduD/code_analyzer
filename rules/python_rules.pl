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
    },
    {
        id       => "PY005",
        pattern  => qr/\byaml\.load\s*\(/,
        message  => "Unsafe YAML deserialization",
        severity => "HIGH",
        fix      => "Use yaml.safe_load() instead of yaml.load()",
    },
    {
        id       => "PY006",
        pattern  => qr/\bhashlib\.(md5|sha1)\s*\(/,
        message  => "Use of weak cryptographic hash function (MD5 or SHA1)",
        severity => "MEDIUM",
        fix      => "Use stronger hashing algorithms like SHA-256",
    },
    {
        id       => "PY007",
        pattern  => qr/\bwhile\s+True\s*:/,
        message  => "Potential infinite loop detected",
        severity => "MEDIUM",
        fix      => "Ensure the loop has a clear exit condition",
    },
    {
        # Advanced Recursion Detection
        id         => "PY008",
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
                # Simple indentation check - if a line has less or equal indentation and is not empty, we exited the function
                # Note: We must also ignore lines that define another function.
                if ($content =~ /^(\s*)\S/ && length($1) <= $func_indent && $content !~ /^\s*def\s+/) {
                    $current_func = "";
                    $has_base_case = 0;
                    return undef;
                }
                
                # Look for base-case patterns (if, elif) within the function
                if ($content =~ /^\s*(?:if|elif)\b/) {
                    $has_base_case = 1;
                }

                # Recursive call
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
                    } else {
                        # It has an if statement. We assume it's safe for now.
                        return undef;
                    }
                }
            }

            return undef;
        }
    },
    {
        id       => "PY009",
        pattern  => qr/\b(?:winreg|_winreg)\.(?:OpenKey|QueryValue|QueryValueEx|QueryInfoKey)\s*\(/,
        message  => "Potential Windows Registry access. Ensure access is intended and does not lead to information disclosure.",
        severity => "MEDIUM",
        fix      => "Review registry access to ensure safe and authorized keys are read.",
    },
    {
        id       => "PY010",
        pattern  => qr/\b(?:winreg|_winreg)\.(?:CreateKey|CreateKeyEx|SetValue|SetValueEx|DeleteKey|DeleteKeyEx|DeleteValue)\s*\(/,
        message  => "Potential Windows Registry modification. Ensure modification is intended and not creating unwanted keys or malware persistence.",
        severity => "HIGH",
        fix      => "Avoid modifying the registry unless strictly necessary, and validate all keys and values.",
    },
    {
        id       => "PY011",
        pattern  => qr/\bsocket\.socket\s*\(\s*(?:socket\.)?(?:AF_INET|AF_INET6|AF_PACKET)\s*,\s*(?:socket\.)?SOCK_RAW(?:.*)|\bpyshark\.LiveCapture\s*\(|\bscapy\.(?:send|sniff)\s*\(/,
        message  => "Potential covert network communication or packet sniffing detected. Use of raw sockets, pyshark, or scapy indicates low-level network access.",
        severity => "HIGH",
        fix      => "Review network access requirements and ensure they are explicitly needed for the application's functionality.",
    },
    {
        id       => "PY012",
        pattern  => qr/\bexec\s*\(\s*(?:base64\.b64decode|zlib\.decompress|codecs\.decode|bytes\.fromhex)\s*\(/,
        message  => "Obfuscated code execution: exec() called with decoded/decompressed data (base64, zlib, hex). This is a classic technique to hide malicious payloads from static analysis.",
        severity => "CRITICAL",
        fix      => "Remove obfuscated exec patterns. All executed code should be readable source code, not encoded blobs.",
    },
    {
        id       => "PY013",
        pattern  => qr/open\s*\(\s*.*?\.(?:sh|bash|bat|cmd|ps1|vbs|vbe|wsf|hta|py|pyw|rb|pl|php)\s*['"][,\s].*?['"w]/,
        message  => "Script dropper detected: a file with an executable extension (.sh/.bat/.ps1/.py/.vbs etc.) is being opened for writing. This is a hallmark of dropper malware that creates a second-stage payload.",
        severity => "CRITICAL",
        fix      => "Do not dynamically write executable script files. Use configuration or data files instead.",
    },
    {
        id       => "PY014",
        pattern  => qr/(?:for|while)\b.*?(?:\n.*?){0,5}\b(?:os\.makedirs|os\.mkdir|pathlib.*?\.mkdir)\s*\(/s,
        message  => "Potential directory bomb: os.makedirs/os.mkdir called inside a loop. This can create a massive number of directories and exhaust filesystem resources (a DoS / resource-exhaustion attack).",
        severity => "HIGH",
        fix      => "Ensure directory creation inside loops is bounded. Add a counter limit and validate the target path.",
    },
    {
        id       => "PY015",
        pattern  => qr/\bctypes\b.*?\b(?:VirtualAlloc|VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|OpenProcess)\b/s,
        message  => "Potential process injection via ctypes: Windows API calls for memory manipulation (VirtualAlloc, WriteProcessMemory, CreateRemoteThread) accessed through ctypes. This is the core technique of Python-based RATs and injectors.",
        severity => "CRITICAL",
        fix      => "Remove process memory injection code. These APIs have no legitimate use in standard Python applications.",
    },
    {
        id       => "PY016",
        pattern  => qr/\bsocket\.connect\s*\(.*?\).*?(?:subprocess|os\.dup2|os\.execv)/s,
        message  => "Potential reverse shell: socket.connect() combined with subprocess or os.dup2/execv detected. This pattern is used to create a remote shell that tunnels stdin/stdout over a network socket.",
        severity => "CRITICAL",
        fix      => "Remove reverse shell code. Use SSH or authorised remote management protocols instead.",
    },
    {
        id       => "PY017",
        pattern  => qr/(?i)(?:stratum\+tcp:\/\/|xmrig|minerd|cpuminer|cryptonight|monero.*?wallet|hashrate)/,
        message  => "Potential cryptominer: references to mining protocols (stratum+tcp), known miner binaries (xmrig, minerd), or mining-related terms detected. Unauthorised cryptomining is malware.",
        severity => "CRITICAL",
        fix      => "Remove all cryptocurrency mining code. Deploying miners without user consent is malware.",
    },
    {
        id       => "PY018",
        pattern  => qr/\bwin32clipboard\b.*?(?:GetClipboardData|SetClipboardData)|pyperclip\.(?:copy|paste)\s*\(.*?(?:replace|sub|re\.)/s,
        message  => "Potential clipboard hijacker: clipboard read/write combined with string substitution detected. This pattern is used by malware to replace clipboard content (e.g., cryptocurrency wallet addresses).",
        severity => "HIGH",
        fix      => "Review clipboard access. Clipboard monitoring and modification should never occur silently in the background.",
    },
]
