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
    }
]
