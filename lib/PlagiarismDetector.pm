package PlagiarismDetector;

use strict;
use warnings;
use Carp;
use File::Basename;

# Tokenize and normalize code for plagiarism / clone detection
# Distinguishes between:
# - Type-1 (Exact Clone): Identical code, differing only in whitespace/comments
# - Type-2 (Renamed Clone): Identical syntax/structure, but variables/identifiers renamed
# - Type-3 (Modified Clone): High structural similarity with minor modifications/insertions

sub detect_clones {
    my ($files, $options) = @_;
    $options ||= {};
    
    my $min_similarity = $options->{min_similarity} // 50; # Minimum % similarity to report
    my $min_lines      = $options->{min_lines} // 4;        # Minimum matching lines
    my $k_gram_size    = $options->{k_gram_size} // 5;     # Token window size

    return { clones => [], summary => { total_clones => 0, highest_similarity => 0, originality_score => 100, duplicated_loc => 0, files_with_clones => 0 } }
        unless $files && ref($files) eq 'ARRAY' && @$files > 0;

    # 1. Preprocess all files into normalized token sequences and line representations
    my %file_data;
    foreach my $file_meta (@$files) {
        my $path = $file_meta->{path};
        my $lang = $file_meta->{lang} || 'generic';
        
        my $parsed = _parse_and_normalize_file($path, $lang);
        if ($parsed && @{$parsed->{tokens}} >= $k_gram_size) {
            $file_data{$path} = $parsed;
        }
    }

    my @file_paths = sort keys %file_data;
    my @clones;
    my %affected_files;
    my $total_duplicated_loc = 0;
    my $highest_similarity = 0;

    # 2. Pairwise comparison of files
    for (my $i = 0; $i < @file_paths; $i++) {
        for (my $j = $i + 1; $j < @file_paths; $j++) {
            my $path_a = $file_paths[$i];
            my $path_b = $file_paths[$j];

            my $data_a = $file_data{$path_a};
            my $data_b = $file_data{$path_b};

            # Compare files using k-gram fingerprinting and sliding window matching
            my $match_result = _compare_files($data_a, $data_b, $k_gram_size, $min_lines);

            if ($match_result && $match_result->{similarity} >= $min_similarity) {
                my $sim = $match_result->{similarity};
                $highest_similarity = $sim if $sim > $highest_similarity;
                $affected_files{$path_a} = 1;
                $affected_files{$path_b} = 1;
                $total_duplicated_loc += $match_result->{matched_lines};

                push @clones, {
                    file_a        => $path_a,
                    file_b        => $path_b,
                    line_a_start  => $match_result->{line_a_start},
                    line_a_end    => $match_result->{line_a_end},
                    line_b_start  => $match_result->{line_b_start},
                    line_b_end    => $match_result->{line_b_end},
                    similarity    => sprintf("%.1f", $sim),
                    clone_type    => $match_result->{clone_type},
                    matched_lines => $match_result->{matched_lines},
                    matched_tokens=> $match_result->{matched_tokens},
                    snippet_a     => $match_result->{snippet_a},
                    snippet_b     => $match_result->{snippet_b},
                };
            }
        }
    }

    # Sort clones by highest similarity descending
    @clones = sort { $b->{similarity} <=> $a->{similarity} } @clones;

    my $originality_score = 100;
    if ($highest_similarity > 0) {
        $originality_score = sprintf("%.1f", 100 - $highest_similarity);
        $originality_score = 0 if $originality_score < 0;
    }

    return {
        clones  => \@clones,
        summary => {
            total_clones       => scalar(@clones),
            highest_similarity => sprintf("%.1f", $highest_similarity),
            originality_score  => $originality_score,
            duplicated_loc     => $total_duplicated_loc,
            files_with_clones  => scalar(keys %affected_files),
        }
    };
}

# Reads file, strips comments, and produces normalized structural tokens
sub _parse_and_normalize_file {
    my ($file, $lang) = @_;

    my $fh;
    unless (open $fh, '<', $file) {
        return undef;
    }
    my @raw_lines = <$fh>;
    close $fh;

    my @lines;
    my @tokens_raw;
    my @tokens_norm;
    my @line_tokens_map; # line_index -> [token_indices]

    # Keyword sets for common languages
    my %keywords = map { $_ => 1 } qw(
        if else elif elsif while for foreach do switch case default break continue return
        function def fn sub procedure func class struct interface enum package import
        from use include require var let const int float double char bool string void
        try catch except finally throw throws new delete public private protected
        static final async await yield lambda select where from in
    );

    for my $idx (0 .. $#raw_lines) {
        my $orig_line = $raw_lines[$idx];
        my $line_num = $idx + 1;
        
        my $clean = $orig_line;
        chomp($clean);
        $clean =~ s/\r$//;

        # Strip inline comments
        $clean =~ s/(?:\/\/|#|--).*//;
        $clean =~ s/\/\*.*?\*\///g;

        $clean =~ s/^\s+//;
        $clean =~ s/\s+$//;

        push @lines, { line_num => $line_num, raw => $orig_line, clean => $clean };

        next if length($clean) == 0;

        # Tokenize line into symbols, identifiers, keywords, and literals
        # Matches words or symbols
        while ($clean =~ /([a-zA-Z_][a-zA-Z0-9_]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\d+\.?\d*|[+\-*\/%&|^!=<>]=?|&&|\|\||::|->|[\{\}\(\)\[\];,])/g) {
            my $tok = $1;
            my $raw_tok = $tok;
            my $norm_tok = $tok;

            if ($tok =~ /^["']/) {
                $norm_tok = '$STR';
            } elsif ($tok =~ /^\d/) {
                $norm_tok = '$NUM';
            } elsif ($tok =~ /^[a-zA-Z_]/) {
                unless (exists $keywords{lc($tok)}) {
                    $norm_tok = '$ID';
                }
            }

            push @tokens_raw, {
                raw      => $raw_tok,
                line_num => $line_num,
            };
            push @tokens_norm, {
                norm     => $norm_tok,
                raw      => $raw_tok,
                line_num => $line_num,
            };
        }
    }

    return {
        path        => $file,
        raw_lines   => \@lines,
        tokens_raw  => \@tokens_raw,
        tokens      => \@tokens_norm,
    };
}

# Compares two files using k-gram rolling hash and longest continuous matching block
sub _compare_files {
    my ($data_a, $data_b, $k, $min_lines) = @_;

    my $toks_a = $data_a->{tokens};
    my $toks_b = $data_b->{tokens};

    return undef if @$toks_a < $k || @$toks_b < $k;

    # Build k-gram map for File A: hash -> [ { start_idx, line_num } ]
    my %kgrams_a;
    for (my $i = 0; $i <= @$toks_a - $k; $i++) {
        my $kgram_norm = join(' ', map { $_->{norm} } @$toks_a[$i .. $i + $k - 1]);
        my $kgram_raw  = join(' ', map { $_->{raw} }  @$toks_a[$i .. $i + $k - 1]);
        push @{$kgrams_a{$kgram_norm}}, {
            idx      => $i,
            line_num => $toks_a->[$i]{line_num},
            raw      => $kgram_raw,
        };
    }

    # Find matching sequences in File B
    my $best_match = {
        len          => 0,
        idx_a        => 0,
        idx_b        => 0,
        exact_tokens => 0,
    };

    my $current_match_len = 0;
    my $current_start_a   = 0;
    my $current_start_b   = 0;
    my $current_exact     = 0;

    my $matched_tokens_total = 0;
    my %matched_b_indices;

    for (my $j = 0; $j <= @$toks_b - $k; $j++) {
        my $kgram_norm = join(' ', map { $_->{norm} } @$toks_b[$j .. $j + $k - 1]);
        
        if (exists $kgrams_a{$kgram_norm}) {
            # Take the best matching anchor in A
            my $match_anchor = $kgrams_a{$kgram_norm}[0];
            my $idx_a = $match_anchor->{idx};

            # Expand match forward
            my $match_len = 0;
            my $exact_count = 0;
            while (($idx_a + $match_len < @$toks_a) &&
                   ($j + $match_len < @$toks_b) &&
                   ($toks_a->[$idx_a + $match_len]{norm} eq $toks_b->[$j + $match_len]{norm})) {
                
                if ($toks_a->[$idx_a + $match_len]{raw} eq $toks_b->[$j + $match_len]{raw}) {
                    $exact_count++;
                }
                $matched_b_indices{$j + $match_len} = 1;
                $match_len++;
            }

            if ($match_len > $best_match->{len}) {
                $best_match->{len}          = $match_len;
                $best_match->{idx_a}        = $idx_a;
                $best_match->{idx_b}        = $j;
                $best_match->{exact_tokens} = $exact_count;
            }
        }
    }

    $matched_tokens_total = scalar(keys %matched_b_indices);
    return undef if $best_match->{len} < $k;

    my $idx_a_start = $best_match->{idx_a};
    my $idx_a_end   = $idx_a_start + $best_match->{len} - 1;
    my $idx_b_start = $best_match->{idx_b};
    my $idx_b_end   = $idx_b_start + $best_match->{len} - 1;

    my $line_a_start = $toks_a->[$idx_a_start]{line_num};
    my $line_a_end   = $toks_a->[$idx_a_end]{line_num};
    my $line_b_start = $toks_b->[$idx_b_start]{line_num};
    my $line_b_end   = $toks_b->[$idx_b_end]{line_num};

    my $matched_lines_a = ($line_a_end - $line_a_start) + 1;
    my $matched_lines_b = ($line_b_end - $line_b_start) + 1;
    my $matched_lines   = ($matched_lines_a + $matched_lines_b) / 2;

    return undef if $matched_lines < $min_lines;

    # Calculate similarity score:
    # Blend token overlap and continuous block size relative to the smaller file
    my $size_a = scalar(@$toks_a);
    my $size_b = scalar(@$toks_b);
    my $min_size = $size_a < $size_b ? $size_a : $size_b;

    my $overlap_pct = ($matched_tokens_total / $min_size) * 100;
    my $block_pct   = ($best_match->{len} / $min_size) * 100;
    my $similarity  = ($overlap_pct * 0.4) + ($block_pct * 0.6);
    $similarity = 100 if $similarity > 100;

    # Determine clone type
    my $exact_ratio = $best_match->{len} > 0 ? ($best_match->{exact_tokens} / $best_match->{len}) : 0;
    my $clone_type;
    if ($exact_ratio >= 0.95) {
        $clone_type = "Type-1 (Exact Clone)";
    } elsif ($exact_ratio >= 0.40) {
        $clone_type = "Type-2 (Renamed Identifiers)";
    } else {
        $clone_type = "Type-3 (Modified Clone)";
    }

    # Extract snippets
    my $snippet_a = _extract_snippet($data_a->{raw_lines}, $line_a_start, $line_a_end);
    my $snippet_b = _extract_snippet($data_b->{raw_lines}, $line_b_start, $line_b_end);

    return {
        similarity    => $similarity,
        clone_type    => $clone_type,
        line_a_start  => $line_a_start,
        line_a_end    => $line_a_end,
        line_b_start  => $line_b_start,
        line_b_end    => $line_b_end,
        matched_lines => int($matched_lines),
        matched_tokens=> $best_match->{len},
        snippet_a     => $snippet_a,
        snippet_b     => $snippet_b,
    };
}

sub _extract_snippet {
    my ($raw_lines, $start, $end) = @_;
    my @lines;
    foreach my $item (@$raw_lines) {
        if ($item->{line_num} >= $start && $item->{line_num} <= $end) {
            push @lines, $item->{raw};
        }
    }
    # Cap to max 25 lines to prevent enormous snippets
    if (@lines > 25) {
        @lines = (@lines[0..23], "... [truncated " . (@lines - 24) . " lines] ...\n");
    }
    return join('', @lines);
}

1;
