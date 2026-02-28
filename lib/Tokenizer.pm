package Tokenizer;

use strict;
use warnings;

# Reads a file, strips comments, and normalizes whitespaces
sub tokenize_file {
    my ($file, $lang) = @_;
    
    open my $fh, '<', $file or die "Could not open file '$file': $!\n";
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
                    $line =~ s/(?:\/\/|#).*//; # PHP has both
                } else {
                    $line =~ s/\/\/.*//;
                }
            }
        
        # 2. Python-Style ('''/""" and #)
        } elsif ($lang eq 'python') {
            if ($in_block_comment) {
                if ($line =~ s/^.*?("""|''')//) { $in_block_comment = 0; } else { $line = ''; }
            }
            if (!$in_block_comment && $line =~ s/("""|''').*?\1//g) { }
            if (!$in_block_comment && $line =~ s/("""|''').*//) { $in_block_comment = 1; }
            if (!$in_block_comment) { $line =~ s/#.*//; }

        # 3. Hash-Style (Ruby, R, Perl, Bash)
        } elsif ($lang =~ /^(ruby|r|perl|bash)$/) {
            if ($lang eq 'ruby' && $line =~ /^=begin/) { $in_block_comment = 1; $line = ''; }
            if ($lang eq 'ruby' && $in_block_comment && $line =~ /^=end/) { $in_block_comment = 0; $line = ''; }
            if ($lang eq 'perl' && $line =~ /^=pod/) { $in_block_comment = 1; $line = ''; }
            if ($lang eq 'perl' && $in_block_comment && $line =~ /^=cut/) { $in_block_comment = 0; $line = ''; }
            
            if (!$in_block_comment) { $line =~ s/#.*//; }

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
        }
        
        # Normalize whitespace
        $line =~ s/^\s+//;
        $line =~ s/\s+$//;
        
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
