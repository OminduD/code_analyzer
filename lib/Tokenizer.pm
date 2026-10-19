package Tokenizer;

use strict;
use warnings;
use Carp;

# Helper to strip single-line comments only when outside string literals
sub _strip_comment {
    my ($line, $marker) = @_;
    return $line unless index($line, $marker) >= 0;
    
    my $in_single = 0;
    my $in_double = 0;
    my $escaped   = 0;
    my $len       = length($line);
    my $idx       = 0;
    my $m_len     = length($marker);
    
    while ($idx < $len) {
        my $char = substr($line, $idx, 1);
        if ($escaped) {
            $escaped = 0;
            $idx++;
            next;
        }
        if ($char eq '\\') {
            $escaped = 1;
            $idx++;
            next;
        }
        if ($char eq '"' && !$in_single) {
            $in_double = !$in_double;
            $idx++;
            next;
        }
        if ($char eq "'" && !$in_double) {
            $in_single = !$in_single;
            $idx++;
            next;
        }
        if (!$in_single && !$in_double) {
            if (substr($line, $idx, $m_len) eq $marker) {
                return substr($line, 0, $idx);
            }
        }
        $idx++;
    }
    return $line;
}

# Reads a file, strips comments, and normalizes whitespaces
sub tokenize_file {
    my ($file, $lang) = @_;
    
    my $fh;
    unless (open $fh, '<', $file) {
        carp "Warning: Could not open file '$file' for tokenization: $!\n";
        return [];
    }
    my @lines = <$fh>;
    close $fh;
    
    my @tokens;
    my $in_block_comment = 0;
    
    for my $i (0 .. $#lines) {
        my $line = $lines[$i];
        my $line_num = $i + 1;
        
        # 1. C-Style (/* */ and //)
        if ($lang =~ /^(c|php|js|java|rust|go|cpp|csharp|swift|kotlin|typescript|scala)$/) {
            if ($in_block_comment) {
                if ($line =~ s/^.*?\*\///) { $in_block_comment = 0; } else { $line = ''; }
            }
            if (!$in_block_comment && $line =~ s/\/\*.*?\*\///g) { }
            if (!$in_block_comment && $line =~ s/\/\*.*//) { $in_block_comment = 1; }
            if (!$in_block_comment) {
                if ($lang eq 'php') {
                    $line = _strip_comment($line, '//');
                    $line = _strip_comment($line, '#');
                } else {
                    $line = _strip_comment($line, '//');
                }
            }
        
        # 2. Python-Style ('''/""" and #)
        } elsif ($lang eq 'python') {
            if ($in_block_comment) {
                if ($line =~ s/^.*?("""|''')//) { $in_block_comment = 0; } else { $line = ''; }
            }
            if (!$in_block_comment && $line =~ s/("""|''').*?\1//g) { }
            if (!$in_block_comment && $line =~ s/("""|''').*//) { $in_block_comment = 1; }
            if (!$in_block_comment) {
                $line = _strip_comment($line, '#');
            }

        # 3. Hash-Style (Ruby, R, Perl, Bash)
        } elsif ($lang =~ /^(ruby|r|perl|bash)$/) {
            if ($lang eq 'ruby' && $line =~ /^=begin/) { $in_block_comment = 1; $line = ''; }
            if ($lang eq 'ruby' && $in_block_comment && $line =~ /^=end/) { $in_block_comment = 0; $line = ''; }
            if ($lang eq 'perl' && $line =~ /^=pod/) { $in_block_comment = 1; $line = ''; }
            if ($lang eq 'perl' && $in_block_comment && $line =~ /^=cut/) { $in_block_comment = 0; $line = ''; }
            
            if (!$in_block_comment) {
                $line = _strip_comment($line, '#');
            }

        # 4. Lua-Style (--[[ ]] and --)
        } elsif ($lang eq 'lua') {
            if ($in_block_comment) {
                if ($line =~ s/^.*?\]\]//) { $in_block_comment = 0; } else { $line = ''; }
            }
            if (!$in_block_comment && $line =~ s/--\[\[.*?\]\]//g) { }
            if (!$in_block_comment && $line =~ s/--\[\[.*//) { $in_block_comment = 1; }
            if (!$in_block_comment) { $line =~ s/--.*//; }
        
        # 4. Assembly & Single Hash styles (# or ;)
        } elsif ($lang eq 'asm') {
            $line =~ s/[#;].*//;

        # 5. Ada & Single Dash styles (--)
        } elsif ($lang eq 'ada') {
            $line =~ s/--.*//;
            
        # 6. COBOL styles (* in Col 7 or *>)
        } elsif ($lang eq 'cobol') {
            # Strip lines starting with * at column 7
            if (length($line) > 6 && substr($line, 6, 1) eq '*') {
                $line = '';
            } else {
                $line =~ s/\*>.*//; # inline floating comments
            }
        
        # 7. Pascal styles ((* *), { } and //)
        } elsif ($lang eq 'pascal') {
            if ($in_block_comment eq 'paren') {
                if ($line =~ s/^.*?\*\)//) { $in_block_comment = 0; } else { $line = ''; }
            } elsif ($in_block_comment eq 'brace') {
                if ($line =~ s/^.*\}//) { $in_block_comment = 0; } else { $line = ''; }
            }
            if (!$in_block_comment && $line =~ s/\(\*.*?\*\)//g) { }
            if (!$in_block_comment && $line =~ s/\{.*?\}//g) { }
            
            if (!$in_block_comment && $line =~ s/\(\*.*//) { $in_block_comment = 'paren'; }
            if (!$in_block_comment && $line =~ s/\{.*//) { $in_block_comment = 'brace'; }
            
            
            if (!$in_block_comment) { $line =~ s/\/\/.*//; }
        
        # 8. Haskell style ({- -} and --)
        } elsif ($lang eq 'haskell') {
            if ($in_block_comment) {
                if ($line =~ s/^.*?-}//) { $in_block_comment = 0; } else { $line = ''; }
            }
            if (!$in_block_comment && $line =~ s/\{-.*?-}//g) { }
            if (!$in_block_comment && $line =~ s/\{-.*//) { $in_block_comment = 1; }
            if (!$in_block_comment) { $line =~ s/--.*//; }

        # 9. Config, Environment & SQL files
        } elsif ($lang =~ /^(env|config|sql)$/) {
            # For SQL files, strip block comments if present
            if ($lang eq 'sql') {
                if ($in_block_comment) {
                    if ($line =~ s/^.*?\*\///) { $in_block_comment = 0; } else { $line = ''; }
                }
                if (!$in_block_comment && $line =~ s/\/\*.*?\*\///g) { }
                if (!$in_block_comment && $line =~ s/\/\*.*//) { $in_block_comment = 1; }
            }
            # Note: For .env and config files, we deliberately DO NOT strip # comments,
            # because developers frequently comment out sensitive credentials instead
            # of rotating them, leaving them exposed in version control.
        }
        
        # Normalize whitespace
        if ($lang eq 'python') {
            # Python relies on indentation, only strip trailing whitespace
            $line =~ s/\s+$//;
        } else {
            # Strip both leading and trailing for other languages
            $line =~ s/^\s+//;
            $line =~ s/\s+$//;
        }
        
        # In Python, we might have fully empty lines (just whitespace) after trailing strip
        if ($lang eq 'python' && $line =~ /^\s*$/) {
            $line = '';
        }

        if (length($line) > 0) {
            push @tokens, {
                line_num => $line_num,
                content  => $line,
            };
        }
    }
    
    return \@tokens;
}

1;
