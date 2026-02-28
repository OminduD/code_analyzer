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
        
        # Strip comments based on language
        if ($lang eq 'c' || $lang eq 'php' || $lang eq 'js' || $lang eq 'java') {
            # Strip block comments
            if ($in_block_comment) {
                if ($line =~ s/^.*?\*\///) {
                    $in_block_comment = 0;
                } else {
                    $line = '';
                }
            }
            if (!$in_block_comment && $line =~ s/\/\*.*?\*\///g) {
                # removed inline block comment
            }
            if (!$in_block_comment && $line =~ s/\/\*.*//) {
                $in_block_comment = 1;
            }
            
            # Strip line comments
            if (!$in_block_comment) {
                if ($lang eq 'c') {
                    $line =~ s/\/\/.*//;
                } else {
                    $line =~ s/(?:\/\/|#).*//; # PHP covers // and #
                }
            }
            
        } elsif ($lang eq 'python') {
            # Python block comments (triple quotes) - this is a bit simplistic, but covers basic cases
            if ($in_block_comment) {
                if ($line =~ s/^.*?("""|''')//) {
                    $in_block_comment = 0;
                } else {
                    $line = '';
                }
            }
            if (!$in_block_comment && $line =~ s/("""|''').*?\1//g) {
                # removed inline triple quotes
            }
            if (!$in_block_comment && $line =~ s/("""|''').*//) {
                $in_block_comment = 1;
            }
            
            # Strip line comments
            if (!$in_block_comment) {
                $line =~ s/#.*//;
            }
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
