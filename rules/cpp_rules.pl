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
    },
    {
        # Advanced Infinite Loop Detection
        id         => "CPP003",
        match_func => sub {
            my ($file, $token, $vulnerabilities) = @_;
            my $content = $token->{content};
            my $line    = $token->{line_num};

            # Standard simple checks
            if ($content =~ /\b(?:while\s*\(\s*1\s*\)|while\s*\(\s*true\s*\)|for\s*\(\s*;\s*;\s*\))/) {
                return {
                    file     => $file,
                    line     => $line,
                    rule_id  => "CPP003",
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
                            rule_id  => "CPP003",
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
                        rule_id  => "CPP003",
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
                        rule_id  => "CPP003",
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
        id         => "CPP004",
        match_func => sub {
            my ($file, $token, $vulnerabilities) = @_;
            our %allocations;
            our %last_file;

            # Reset state for a new file
            if (!$last_file{cpp_mem} || $last_file{cpp_mem} ne $file) {
                %allocations = ();
                $last_file{cpp_mem} = $file;
            }

            my $content = $token->{content};
            my $line    = $token->{line_num};

            # Track new
            if ($content =~ /\b([a-zA-Z0-9_]+)\s*=\s*new\b/) {
                my $var = $1;
                $allocations{$var} = $line;
            }

            # Track delete
            if ($content =~ /\bdelete\s+(?:\[\]\s+)?([a-zA-Z0-9_]+)\b/) {
                my $var = $1;
                delete $allocations{$var} if exists $allocations{$var};
            }

            # Flag reassignment before delete
            if ($content =~ /\b([a-zA-Z0-9_]+)\s*=\s*new\b/) {
                my $var = $1;
                if (exists $allocations{$var} && $allocations{$var} != $line) {
                    my $old_line = $allocations{$var};
                    return {
                        file     => $file,
                        line     => $line,
                        rule_id  => "CPP004",
                        message  => "Potential Memory Leak: '$var' allocated at line $old_line is reallocated or not deleted.",
                        severity => "HIGH",
                        fix      => "Ensure every 'new' is paired with a 'delete' or use smart pointers (std::unique_ptr).",
                        snippet  => $content,
                    };
                }
            }
            return undef;
        }
    },
    {
        id       => "CPP005",
        pattern  => qr/\b(?:RegOpenKey|RegOpenKeyEx|RegQueryValue|RegQueryValueEx)\s*\(/,
        message  => "Potential Windows Registry access. Ensure access is intended and does not lead to information disclosure.",
        severity => "MEDIUM",
        fix      => "Review registry access to ensure safe and authorized keys are read.",
    },
    {
        id       => "CPP006",
        pattern  => qr/\b(?:RegCreateKey|RegCreateKeyEx|RegSetValue|RegSetValueEx|RegDeleteKey|RegDeleteKeyEx|RegDeleteValue)\s*\(/,
        message  => "Potential Windows Registry modification. Ensure modification is intended and not creating unwanted keys or malware persistence.",
        severity => "HIGH",
        fix      => "Avoid modifying the registry unless strictly necessary, and validate all keys and values.",
    },
    {
        id       => "CPP007",
        pattern  => qr/\b(?:socket\s*\(\s*(?:AF_INET|AF_INET6|PF_INET|PF_INET6|AF_PACKET|PF_PACKET)\s*,\s*SOCK_RAW\s*,\s*|pcap_open_live\s*\(|pcap_create\s*\(|setsockopt\s*\(\s*[^,]+,\s*SOL_SOCKET\s*,\s*SO_BINDTODEVICE)/,
        message  => "Potential covert network communication or packet sniffing detected. Use of raw sockets or pcap indicates low-level network access.",
        severity => "HIGH",
        fix      => "Review network access requirements and ensure they are explicitly needed for the application's functionality.",
    },
    {
        id       => "CPP999",
        pattern  => qr/(?i)(Software(?:\\|\/)Microsoft(?:\\|\/)Windows(?:\\|\/)CurrentVersion(?:\\|\/)Run|\.config(?:\\|\/)autostart)/,
        message  => "Potential malware persistence mechanism detected (Windows Run key or Linux autostart)",
        severity => "HIGH",
        fix      => "Remove auto-start functionality unless explicitly required by the application",
    },
    {
        id       => "CPP008",
        pattern  => qr/\b(?:VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|RtlCreateUserThread|QueueUserAPC)\s*\(/,
        message  => "Process injection API detected (VirtualAllocEx/WriteProcessMemory/CreateRemoteThread). Core technique used by RATs, trojans, and rootkits to inject code into other processes.",
        severity => "CRITICAL",
        fix      => "Remove process injection code. These APIs should not appear in legitimate application code.",
    },
    {
        id       => "CPP009",
        pattern  => qr/\b(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess)\s*\(\s*\)|ptrace\s*\(\s*PTRACE_TRACEME/,
        message  => "Anti-debugging technique detected. Malware uses these APIs to detect and evade analysis environments.",
        severity => "HIGH",
        fix      => "Remove debugger detection code. If DRM is required, use a vetted and documented library.",
    },
    {
        id       => "CPP010",
        pattern  => qr/(?:CreateFile|std::ofstream)\s*\(.*?\).*?(?:WriteFile|\.write\s*\()/s,
        message  => "File dropper pattern: file creation combined with binary write. Used by malware droppers to write second-stage payloads to disk.",
        severity => "HIGH",
        fix      => "Review all file write logic. Ensure filenames are strictly controlled and executable content is never written dynamically.",
    },
    {
        id       => "CPP011",
        pattern  => qr/\bCryptEncrypt\s*\(/,
        message  => "CryptEncrypt API detected. Bulk file encryption in a loop is the core mechanic of ransomware.",
        severity => "HIGH",
        fix      => "Review all encryption logic involving files. Bulk encryption of user data is a ransomware indicator.",
    },
    {
        id       => "CPP012",
        pattern  => qr/(?:for|while)\s*\(.*?(?:\n.*?){0,5}\b(?:CreateDirectory|mkdir|std::filesystem::create_directories)\s*\(/s,
        message  => "Potential directory bomb: directory-creation call inside a loop can exhaust filesystem resources (DoS).",
        severity => "HIGH",
        fix      => "Bound directory creation in loops. Validate target paths and add a hard creation limit.",
    }
]
