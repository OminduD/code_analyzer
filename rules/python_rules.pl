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
        # Recursion Detection
        id         => "PY008",
        match_func => sub {
            my ($file, $token, $vulnerabilities) = @_;
            our $current_func;
            our %last_file;
            our $func_indent = 0;

            if (!$last_file{py_rec} || $last_file{py_rec} ne $file) {
                $current_func = "";
                $last_file{py_rec} = $file;
            }

            my $content = $token->{content};
            my $line    = $token->{line_num};

            # Detect function definition: def my_func(args):
            if ($content =~ /^(\s*)def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/) {
                $func_indent = length($1);
                $current_func = $2;
                return undef;
            }

            # If we are inside a function (indentation is greater than the def line)
            if ($current_func) {
                # Simple indentation check - if a line has less or equal indentation and is not empty, we exited the function
                if ($content =~ /^(\s*)\S/ && length($1) <= $func_indent) {
                    $current_func = "";
                } elsif ($content =~ /\b$current_func\s*\(/) {
                    return {
                        file     => $file,
                        line     => $line,
                        rule_id  => "PY008",
                        message  => "Recursive function call detected: '$current_func' calls itself.",
                        severity => "LOW",
                        fix      => "Ensure the recursion has a proper base case to avoid RecursionError.",
                        snippet  => $content,
                    };
                }
            }

            return undef;
        }
    }
]
