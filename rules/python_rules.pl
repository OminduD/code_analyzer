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
    }
]
