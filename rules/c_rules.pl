[
    {
        id       => "C001",
        pattern  => qr/\bgets\s*\(/,
        message  => "Use of unsafe function gets()",
        severity => "HIGH",
        fix      => "Use fgets() instead",
    },
    {
        id       => "C002",
        pattern  => qr/\bstrcpy\s*\(/,
        message  => "Use of unsafe function strcpy()",
        severity => "HIGH",
        fix      => "Use strncpy() instead",
    },
    {
        id       => "C003",
        pattern  => qr/\bsprintf\s*\(/,
        message  => "Potential buffer overflow with sprintf()",
        severity => "MEDIUM",
        fix      => "Use snprintf() instead",
    },
    {
        id       => "C004",
        pattern  => qr/\bsystem\s*\(/,
        message  => "Use of system() can lead to command injection",
        severity => "HIGH",
        fix      => "Use exec() family functions instead",
    },
    {
        id       => "C005",
        pattern  => qr/(?i)password\s*=\s*["'][^"']+["']/,
        message  => "Hardcoded password detected",
        severity => "HIGH",
        fix      => "Use environment variables or secure vault",
    },
    {
        id       => "C006",
        pattern  => qr/\bscanf\s*\(\s*["'][^"']*\%s/,
        message  => "Potential buffer overflow with scanf() relying on %s without width limits",
        severity => "HIGH",
        fix      => "Specify maximum field width, e.g., %255s",
    },
    {
        id       => "C007",
        pattern  => qr/\brand\s*\(/,
        message  => "Use of insecure pseudo-random number generator rand()",
        severity => "MEDIUM",
        fix      => "Use more secure alternatives or cryptographically secure generators",
    },
    {
        # Advanced Infinite Loop Detection
        id         => "C008",
        match_func => sub {
            my ($file, $token, $vulnerabilities) = @_;
            my $content = $token->{content};
            my $line    = $token->{line_num};

            # Standard simple checks
            if ($content =~ /\b(?:while\s*\(\s*1\s*\)|while\s*\(\s*true\s*\)|for\s*\(\s*;\s*;\s*\))/) {
                return {
                    file     => $file,
                    line     => $line,
                    rule_id  => "C008",
                    message  => "Potential infinite loop detected (hardcoded loop condition).",
                    severity => "MEDIUM",
                    fix      => "Ensure the loop has a clear exit condition",
                    snippet  => $content,
                };
            }

            # Advanced For-Loop checks
            # Parse components: for (init; condition; increment)
            if ($content =~ /\bfor\s*\(\s*[^;]*;\s*([a-zA-Z0-9_]+)\s*(?:<|>|<=|>=|!=|==)\s*[^;]+;\s*([a-zA-Z0-9_\-\+]+)\s*\)/) {
                my $cond_var = $1;
                my $inc_stmt = $2;

                # Mismatched Loop Variables (e.g. for(int i=0; j<10; i++))
                if ($inc_stmt =~ /([a-zA-Z0-9_]+)/) {
                    my $inc_var = $1;
                    if ($cond_var ne $inc_var) {
                        return {
                            file     => $file,
                            line     => $line,
                            rule_id  => "C008",
                            message  => "Infinite Loop: The loop condition variable '$cond_var' does not match the incremented variable '$inc_var'.",
                            severity => "HIGH",
                            fix      => "Ensure the correct variable is incremented/decremented to meet the exit condition.",
                            snippet  => $content,
                        };
                    }
                }

                # Wrong Direction Loop (e.g. for(int i=0; i<10; i--))
                # Using naive regex to catch common mistakes for now.
                if ($content =~ /\bfor\s*\([^;]*;\s*[a-zA-Z0-9_]+\s*<\s*[^;]+;\s*[a-zA-Z0-9_]+--\s*\)/) {
                    return {
                        file     => $file,
                        line     => $line,
                        rule_id  => "C008",
                        message  => "Infinite Loop: Loop increments away from the exit condition (checks < but uses --).",
                        severity => "HIGH",
                        fix      => "Reverse the increment direction to approach the exit condition.",
                        snippet  => $content,
                    };
                }
                if ($content =~ /\bfor\s*\([^;]*;\s*[a-zA-Z0-9_]+\s*>\s*[^;]+;\s*[a-zA-Z0-9_]+\+\+\s*\)/) {
                    return {
                        file     => $file,
                        line     => $line,
                        rule_id  => "C008",
                        message  => "Infinite Loop: Loop increments away from the exit condition (checks > but uses ++).",
                        severity => "HIGH",
                        fix      => "Reverse the increment direction to approach the exit condition.",
                        snippet  => $content,
                    };
                }
            }

            return undef;
        }
    },
    {
        # Memory Leak Detection
        id         => "C009",
        match_func => sub {
            my ($file, $token, $vulnerabilities) = @_;
            our %allocations;
            our %last_file;

            # Reset state for a new file
            if (!$last_file{c_mem} || $last_file{c_mem} ne $file) {
                %allocations = ();
                $last_file{c_mem} = $file;
            }

            my $content = $token->{content};
            my $line    = $token->{line_num};

            # Track malloc/calloc/realloc
            if ($content =~ /\b([a-zA-Z0-9_]+)\s*=\s*(?:[a-zA-Z0-9_\s\*]*\))?\s*(?:malloc|calloc|realloc)\s*\(/) {
                my $var = $1;
                $allocations{$var} = $line;
            }

            # Track free
            if ($content =~ /\bfree\s*\(\s*([a-zA-Z0-9_]+)\s*\)/) {
                my $var = $1;
                delete $allocations{$var} if exists $allocations{$var};
            }

            # If we reach the end of the file in the analyzer loop, we should ideally check remaining allocations.
            # However, for simplicity per-token, we'll flag any new allocation that overwrites an un-freed one.
            if ($content =~ /\b([a-zA-Z0-9_]+)\s*=\s*(?:[a-zA-Z0-9_\s\*]*\))?\s*(?:malloc|calloc|realloc)\s*\(/) {
                my $var = $1;
                if (exists $allocations{$var} && $allocations{$var} != $line) {
                    my $old_line = $allocations{$var};
                    return {
                        file     => $file,
                        line     => $line,
                        rule_id  => "C009",
                        message  => "Potential Memory Leak: '$var' allocated at line $old_line is reallocated or not freed.",
                        severity => "HIGH",
                        fix      => "Ensure every malloc/calloc is paired with a free()",
                        snippet  => $content,
                    };
                }
            }
            return undef;
        }
    },
    {
        # Advanced Recursion Detection
        id         => "C010",
        match_func => sub {
            my ($file, $token, $vulnerabilities) = @_;
            our $current_func;
            our %last_file;
            our $has_base_case = 0;

            if (!$last_file{c_rec} || $last_file{c_rec} ne $file) {
                $current_func = "";
                $has_base_case = 0;
                $last_file{c_rec} = $file;
            }

            my $content = $token->{content};
            my $line    = $token->{line_num};

            # Very basic C function definition extraction: type name(args) { ...
            if ($content =~ /^[a-zA-Z_][a-zA-Z0-9_\s\*]*\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^;]*$/) {
                if ($content !~ /;\s*$/) {
                    $current_func  = $1;
                    $has_base_case = 0;
                }
            }

            if ($current_func) {
                # Look for typical base-case mechanisms (if statements or return)
                if ($content =~ /\b(if|return)\b/) {
                    $has_base_case = 1;
                }

                # Recursive function call
                if ($content =~ /\b$current_func\s*\(/) {
                    # Don't flag the definition line itself
                    if ($content !~ /^[a-zA-Z_][a-zA-Z0-9_\s\*]*\s+$current_func\s*\(/) {
                        
                        if (!$has_base_case) {
                            return {
                                file     => $file,
                                line     => $line,
                                rule_id  => "C010",
                                message  => "Uncontrolled Recursion (Stack Overflow): '$current_func' calls itself without a prior base-case check (if/return).",
                                severity => "CRITICAL",
                                fix      => "Add a conditional base case (e.g. `if (condition) return;`) before recursing.",
                                snippet  => $content,
                            };
                        } else {
                            # It is recursive, but has an `if` so we treat it as potentially safe
                            # Return undef to hide it entirely, or return a LOW warning. Let's hide it to reduce false positives.
                            return undef;
                        }
                    }
                }
            }

            # Basic reset at end of brace (very naive)
            if ($content =~ /^}\s*$/) {
                $current_func  = "";
                $has_base_case = 0;
            }

            return undef;
        }
    },
    {
        id       => "C011",
        pattern  => qr/\b(?:RegOpenKey|RegOpenKeyEx|RegQueryValue|RegQueryValueEx)\s*\(/,
        message  => "Potential Windows Registry access. Ensure access is intended and does not lead to information disclosure.",
        severity => "MEDIUM",
        fix      => "Review registry access to ensure safe and authorized keys are read.",
    },
    {
        id       => "C012",
        pattern  => qr/\b(?:RegCreateKey|RegCreateKeyEx|RegSetValue|RegSetValueEx|RegDeleteKey|RegDeleteKeyEx|RegDeleteValue)\s*\(/,
        message  => "Potential Windows Registry modification. Ensure modification is intended and not creating unwanted keys or malware persistence.",
        severity => "HIGH",
        fix      => "Avoid modifying the registry unless strictly necessary, and validate all keys and values.",
    },
    {
        id       => "C013",
        pattern  => qr/\b(?:socket\s*\(\s*(?:AF_INET|AF_INET6|PF_INET|PF_INET6|AF_PACKET|PF_PACKET)\s*,\s*SOCK_RAW\s*,\s*|pcap_open_live\s*\(|pcap_create\s*\(|setsockopt\s*\(\s*[^,]+,\s*SOL_SOCKET\s*,\s*SO_BINDTODEVICE)/,
        message  => "Potential covert network communication or packet sniffing detected. Use of raw sockets or pcap indicates low-level network access.",
        severity => "HIGH",
        fix      => "Review network access requirements and ensure they are explicitly needed for the application's functionality.",
    },
    {
        id       => "C999",
        pattern  => qr/(?i)(Software(?:\\|\/)Microsoft(?:\\|\/)Windows(?:\\|\/)CurrentVersion(?:\\|\/)Run|\.config(?:\\|\/)autostart)/,
        message  => "Potential malware persistence mechanism detected (Windows Run key or Linux autostart)",
        severity => "HIGH",
        fix      => "Remove auto-start functionality unless explicitly required by the application",
    },
    {
        id       => "C014",
        pattern  => qr/\b(?:VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|RtlCreateUserThread|QueueUserAPC)\s*\(/,
        message  => "Process injection API detected (VirtualAllocEx/WriteProcessMemory/CreateRemoteThread). These are the core Windows APIs used by RATs, trojans, and rootkits to inject malicious code into other processes.",
        severity => "CRITICAL",
        fix      => "Remove process injection code. These APIs should never appear in legitimate application code.",
    },
    {
        id       => "C015",
        pattern  => qr/\b(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess)\s*\(\s*\)|ptrace\s*\(\s*PTRACE_TRACEME/,
        message  => "Anti-debugging technique detected: IsDebuggerPresent, CheckRemoteDebuggerPresent, or ptrace(PTRACE_TRACEME). Malware uses these to detect and evade security analysis tools.",
        severity => "HIGH",
        fix      => "Remove debugger-detection code. If DRM is required, use a vetted and documented library.",
    },
    {
        id       => "C016",
        pattern  => qr/CreateFile\s*\(.*?\).*?(?:WriteFile|fwrite)\s*\(/s,
        message  => "File dropper pattern: CreateFile followed by WriteFile detected. This pattern is used by malware to write second-stage payloads (executables, scripts) to disk.",
        severity => "HIGH",
        fix      => "Review file creation and write logic. Ensure filenames are strictly controlled and do not produce executable files.",
    },
    {
        id       => "C017",
        pattern  => qr/\bCryptEncrypt\s*\(/,
        message  => "CryptEncrypt API detected. When used inside a file iteration loop this is the signature behaviour of ransomware (bulk-encrypting user files).",
        severity => "HIGH",
        fix      => "Review all encryption logic involving files. Bulk encryption of user data directories is a ransomware indicator.",
    },
    {
        id       => "C018",
        pattern  => qr/(?:for|while)\s*\(.*?(?:\n.*?){0,5}\b(?:CreateDirectory|mkdir)\s*\(/s,
        message  => "Potential directory bomb: CreateDirectory or mkdir called inside a loop. This can create a massive number of directories rapidly and exhaust filesystem resources (DoS).",
        severity => "HIGH",
        fix      => "Bound directory creation in loops. Add a hard limit and validate the target path.",
    }
    ,
    {
        id       => "C019",
        pattern  => qr/\bfork\s*\(\s*\)/,
        message  => "fork() detected. When called inside a loop or recursive function without bounds this creates a fork bomb — processes spawn exponentially until the PID table is exhausted and the system crashes.",
        severity => "HIGH",
        fix      => "Never call fork() inside a loop or recursive function without strict limits. Use a bounded process pool or thread pool instead.",
    },
    {
        id       => "C020",
        pattern  => qr/(?:for|while)\s*\(.*?(?:\n.*?){0,8}\b(?:CreateProcess|_spawnl|_spawnv|exec[lv]p?)\s*\(/s,
        message  => "Process creation bomb: CreateProcess/_spawn/exec family call inside a loop with no apparent bound. This can rapidly exhaust PID table, memory, and file descriptors.",
        severity => "HIGH",
        fix      => "Always bound process creation in loops. Use a semaphore or process pool to limit concurrency.",
    },
    {
        id       => "C021",
        type     => "malware",
        pattern  => qr/(?:DETACHED_PROCESS|CREATE_NO_WINDOW|SW_HIDE)\s*\|?.*?CreateProcess\s*\(/s,
        message  => "Hidden process creation via CreateProcess with DETACHED_PROCESS or CREATE_NO_WINDOW flag. Malware uses these flags to launch processes with no visible window or terminal.",
        severity => "HIGH",
        fix      => "Avoid hidden process creation. Legitimate background services should be started through the system service manager (SCM/systemd).",
    },
    {
        id       => "C022",
        type     => "vulnerability",
        cwe      => "CWE-134",
        pattern  => qr/\b(?:printf|fprintf|vprintf|vfprintf|syslog)\s*\(\s*(?:[a-zA-Z0-9_\-\>]+|[a-zA-Z0-9_\-\>]+\s*,\s*[a-zA-Z0-9_\-\>]+)\s*\)/,
        message  => "Potential Format String vulnerability: non-literal format string passed to printf/syslog family",
        severity => "CRITICAL",
        fix      => "Always pass a string literal format specifier, e.g., printf(\"%s\", user_str)",
    },
    {
        id       => "C023",
        type     => "vulnerability",
        cwe      => "CWE-120",
        pattern  => qr/\bstrcat\s*\(/,
        message  => "Use of unsafe function strcat() can lead to buffer overflow",
        severity => "HIGH",
        fix      => "Use strncat() or snprintf() with explicit buffer size bounds",
    },
    {
        id       => "C024",
        type     => "vulnerability",
        cwe      => "CWE-732",
        pattern  => qr/\bchmod\s*\(\s*[^,]+,\s*(?:0777|S_IRWXU\s*\|\s*S_IRWXG\s*\|\s*S_IRWXO)\)/,
        message  => "Insecure world-writable file permissions (0777)",
        severity => "HIGH",
        fix      => "Restrict permissions to minimum necessary (e.g. 0640 or 0750)",
    },
    {
        id       => "CERR001",
        type     => "error",
        cwe      => "CWE-480",
        pattern  => qr/\bif\s*\(\s*[a-zA-Z0-9_]+\s*=\s*[^=]/,
        message  => "Accidental assignment in 'if' conditional statement instead of equality comparison",
        severity => "HIGH",
        fix      => "Replace '=' assignment with '==' comparison operator",
    },
    {
        id       => "CERR002",
        type     => "error",
        cwe      => "CWE-369",
        pattern  => qr/[a-zA-Z0-9_\)]\s*[\/%]\s*0(?:\.0*)?(?!\d)/,
        message  => "Division or modulo by literal zero causes SIGFPE crash or undefined behavior",
        severity => "HIGH",
        fix      => "Verify divisor is non-zero before dividing",
    },
    {
        id       => "CERR003",
        type     => "error",
        cwe      => "CWE-561",
        pattern  => qr/\b(?:return|exit)\b.*?;[ \t]*\S+/,
        message  => "Dead code detected immediately following return or exit statement",
        severity => "LOW",
        fix      => "Remove unreachable code after return or exit",
    },
    {
        id       => "CERR004",
        type     => "error",
        cwe      => "CWE-415",
        pattern  => qr/\bfree\s*\(\s*([a-zA-Z0-9_]+)\s*\)\s*;.*?\bfree\s*\(\s*\1\s*\)/s,
        message  => "Potential Double Free vulnerability: pointer freed multiple times without being set to NULL",
        severity => "CRITICAL",
        fix      => "Set pointer to NULL immediately after calling free(ptr)",
    }
]
