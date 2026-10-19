package Reporter;

use strict;
use warnings;
use Term::ANSIColor;
use JSON::PP;
use File::Basename;
use File::Spec;
use FindBin;
use MIME::Base64;
use Carp;

sub print_terminal {
    my ($vulnerabilities, $score_data, $metadata, $plagiarism_data) = @_;
    
    print color('bold cyan');
    print "\n";
    print " ╔══════════════════════════════════════════════════════════════╗\n";
    print " ║                                                              ║\n";
    print " ║           PERL STATIC CODE SECURITY ANALYZER                 ║\n";
    print " ║         Security, Code Quality & Plagiarism Engine           ║\n";
    print " ║                                                              ║\n";
    print " ╚══════════════════════════════════════════════════════════════╝\n";
    print color('reset');
    
    if ($metadata) {
        print color('bright_black');
        print " ┌─[ Scan Metadata ]────────────────────────────────────────────┐\n";
        printf(" │ %-15s: %-42s │\n", "Date", $metadata->{timestamp});
        printf(" │ %-15s: %-42s │\n", "Target Path", $metadata->{target_path});
        printf(" │ %-15s: %-42s │\n", "Language", uc($metadata->{language}));
        printf(" │ %-15s: %-42s │\n", "Files Scanned", $metadata->{files_scanned});
        printf(" │ %-15s: %-42s │\n", "Total LOC", $metadata->{total_loc});
        printf(" │ %-15s: %-42s │\n", "Duration", $metadata->{duration_secs} . "s");
        print " └──────────────────────────────────────────────────────────────┘\n\n";
        print color('reset');
    }
    
    my %color_map = (
        CRITICAL => 'bold bright_magenta',
        HIGH     => 'bold bright_red',
        MEDIUM   => 'bold bright_yellow',
        LOW      => 'bold bright_green',
        INFO     => 'bold bright_cyan',
    );

    my %type_map = (
        vulnerability => 'VULN',
        error         => 'BUG/ERROR',
        malware       => 'MALWARE',
        secret        => 'SECRET',
    );
    
    if (!@$vulnerabilities) {
        print color('bold bright_green'), " [OK] PERFECT. Zero security vulnerabilities or code errors found!\n\n", color('reset');
    }
    
    foreach my $vuln (@$vulnerabilities) {
        my $sev = uc($vuln->{severity} || 'LOW');
        my $cat_color = $color_map{$sev} || 'reset';
        my $type = uc($vuln->{type} || 'VULNERABILITY');
        my $cwe_str = $vuln->{cwe} ? " [$vuln->{cwe}]" : "";
        
        print color($cat_color), " > [$sev] ", color('reset');
        print color('bold white'), "$vuln->{file}:$vuln->{line}", color('reset');
        print color('bright_black'), " (Rule: $vuln->{rule_id}$cwe_str) ", color('bold cyan'), "[$type]\n", color('reset');
        print "    ├─ Message : $vuln->{message}\n";
        print "    ├─ Snippet : ", color('bright_red'), "$vuln->{snippet}\n", color('reset');
        print "    └─ Fix     : ", color('bright_green'), "$vuln->{fix}\n", color('reset');
        print "\n";
    }

    # Plagiarism / Code Clones Section
    if ($plagiarism_data && $plagiarism_data->{summary} && $plagiarism_data->{summary}{total_clones} > 0) {
        my $p_sum = $plagiarism_data->{summary};
        print color('bold magenta');
        print " ╭── Plagiarism & Code Clones ──────────────────────────────╮\n";
        print color('reset');
        printf(" │  Total Clones Detected : %-31s │\n", $p_sum->{total_clones});
        printf(" │  Highest Similarity    : %-31s │\n", $p_sum->{highest_similarity} . "%");
        printf(" │  Originality Index     : %-31s │\n", $p_sum->{originality_score} . "%");
        printf(" │  Duplicated LOC        : %-31s │\n", $p_sum->{duplicated_loc} . " lines");
        print color('bold magenta'), " ╰──────────────────────────────────────────────────────────╯\n", color('reset');

        print color('bold white'), "\n  Top Duplication & Clone Matches:\n", color('reset');
        for my $cl (@{$plagiarism_data->{clones}}[0 .. (@{$plagiarism_data->{clones}} > 5 ? 4 : $#{$plagiarism_data->{clones}})]) {
            my $sim_color = $cl->{similarity} >= 80 ? 'bold bright_red' : ($cl->{similarity} >= 60 ? 'bold bright_yellow' : 'bold bright_green');
            print color($sim_color), "   • [$cl->{similarity}% Match] ", color('reset');
            print color('bold cyan'), "$cl->{file_a}:$cl->{line_a_start}-$cl->{line_a_end}", color('reset');
            print " ⟷ ";
            print color('bold cyan'), "$cl->{file_b}:$cl->{line_b_start}-$cl->{line_b_end}", color('reset');
            print color('bright_black'), " ($cl->{clone_type})\n", color('reset');
        }
        print "\n";
    }
    
    print "\n", color('bold cyan'), " ╭── Executive Summary ─────────────────────────╮", color('reset'), "\n";
    
    my $cat_color = $score_data->{category} eq 'CRITICAL' ? 'bold bright_red' :
                    $score_data->{category} eq 'MODERATE' ? 'bold bright_yellow' : 'bold bright_green';
                    
    printf(" │  Total Risk Score    : %-22s │\n", $score_data->{score});
    print  " │  Risk Category       : ";
    print color($cat_color), sprintf("%-22s", $score_data->{category}), color('reset'), " │\n";
    printf(" │  Code Quality Index  : %-22s │\n", $score_data->{quality_score} . "% (Grade: $score_data->{quality_grade})");
    printf(" │  Vulnerabilities     : %-22s │\n", $score_data->{by_type}{vulnerability} // 0);
    printf(" │  Code Errors / Bugs  : %-22s │\n", $score_data->{by_type}{error} // 0);
    printf(" │  Malware Indicators  : %-22s │\n", $score_data->{by_type}{malware} // 0);
    printf(" │  Exposed Secrets     : %-22s │\n", $score_data->{by_type}{secret} // 0);
    if ($plagiarism_data && $plagiarism_data->{summary}) {
        printf(" │  Max Plagiarism Sim  : %-22s │\n", ($plagiarism_data->{summary}{highest_similarity} // 0) . "%");
    }
    print color('bold cyan'), " ╰──────────────────────────────────────────────╯", color('reset'), "\n\n";
}

sub generate_json {
    my ($vulnerabilities, $score_data, $metadata, $plagiarism_data, $output_file) = @_;
    
    my %report = (
        metadata        => $metadata,
        summary         => $score_data,
        vulnerabilities => $vulnerabilities,
        plagiarism      => $plagiarism_data // {},
    );
    
    my $json = JSON::PP->new->pretty->encode(\%report);
    
    my $fh;
    unless (open $fh, '>', $output_file) {
        carp "Error: Could not open JSON file '$output_file' for writing: $!\n";
        return;
    }
    print $fh $json;
    close $fh;
    
    print color('bright_black'), " [OK] JSON report generated: $output_file\n", color('reset');
}

sub generate_html {
    my ($vulnerabilities, $score_data, $metadata, $plagiarism_data, $output_file) = @_;
    
    $plagiarism_data ||= {
        clones  => [],
        summary => { total_clones => 0, highest_similarity => 0, originality_score => 100, duplicated_loc => 0, files_with_clones => 0 }
    };

    # Load and encode logo from components/ui/logo-white.webp for standalone embedding
    my $logo_data_uri = '';
    my @candidate_logo_paths = (
        File::Spec->catfile($FindBin::Bin, '..', 'components', 'ui', 'logo-white.webp'),
        File::Spec->catfile('components', 'ui', 'logo-white.webp'),
        '/home/omindu/Documents/Perl/code_analyzer/components/ui/logo-white.webp',
    );
    for my $lpath (@candidate_logo_paths) {
        if (-f $lpath && open(my $lfh, '<:raw', $lpath)) {
            local $/;
            my $raw_logo = <$lfh>;
            close $lfh;
            $logo_data_uri = 'data:image/webp;base64,' . MIME::Base64::encode_base64($raw_logo, '');
            last;
        }
    }

    my $logo_img_tag = $logo_data_uri
        ? qq{<img src="$logo_data_uri" alt="OminduD Logo" class="footer-logo-img">}
        : qq{<span style="font-family: 'JetBrains Mono', monospace; font-weight: 900; color: #fff; font-size: 1.1rem;">OD</span>};

    my $vuln_rows = '';
    my %counts = ( CRITICAL => 0, HIGH => 0, MEDIUM => 0, LOW => 0 );
    my %type_counts = (
        vulnerability => 0,
        error         => 0,
        malware       => 0,
        secret        => 0,
    );
    my %rule_counts;
    my %file_counts;
    my %posture_hits = (
        INJECTION    => 0,
        EXFILTRATION => 0,
        PERSISTENCE  => 0,
        ISOLATION    => 0,
        HYGIENE      => 0,
    );
    
    foreach my $vuln (@$vulnerabilities) {
        my $sev = uc($vuln->{severity} || 'LOW');
        $sev = 'HIGH' unless exists $counts{$sev};
        $counts{$sev}++;
        
        my $type = lc($vuln->{type} || 'vulnerability');
        $type = 'vulnerability' unless exists $type_counts{$type};
        $type_counts{$type}++;

        my $rule = $vuln->{rule_id} || 'GEN001';
        $rule_counts{$rule}++;
        
        my $sev_class = lc($sev);
        my $file_name = basename($vuln->{file});
        $file_counts{$file_name}++;
        
        # Categorize for Security Posture
        my $msg_rule = lc(($vuln->{message} || '') . ' ' . $rule);
        if ($msg_rule =~ /(inject|eval|exec|cmd|shell|sql|popen|call)/) {
            $posture_hits{INJECTION}++;
        } elsif ($msg_rule =~ /(net|exfil|socket|packet|passwd|shadow|token|secret|key|cred)/) {
            $posture_hits{EXFILTRATION}++;
        } elsif ($msg_rule =~ /(reg|run|autostart|persist|replicat|worm|updater)/) {
            $posture_hits{PERSISTENCE}++;
        } elsif ($msg_rule =~ /(fork|process|hidden|miner|bomb|malware|detached)/) {
            $posture_hits{ISOLATION}++;
        } else {
            $posture_hits{HYGIENE}++;
        }
        
        my $snippet = _escape_html($vuln->{snippet});
        my $message = _escape_html($vuln->{message});
        my $fix     = _escape_html($vuln->{fix});
        my $file_path = _escape_html($vuln->{file});
        my $cwe_badge = $vuln->{cwe} ? qq{<span class="cwe-badge">$vuln->{cwe}</span>} : '';
        my $type_label = uc($type);
        
        $vuln_rows .= <<"HTML";
            <tr class="vuln-row" data-severity="$sev_class" data-type="$type" data-search="$file_name $vuln->{line} $rule $sev $type $message">
                <td class="col-loc" title="$file_path">
                    <span class="file-name">$file_name</span>
                    <span class="line-badge">Line $vuln->{line}</span>
                </td>
                <td class="col-type"><span class="type-badge type-$type">$type_label</span></td>
                <td class="col-rule"><span class="rule-badge">$rule</span>$cwe_badge</td>
                <td class="col-sev"><span class="sev-badge sev-$sev_class">$sev</span></td>
                <td class="col-msg">$message</td>
                <td class="col-code"><code>$snippet</code></td>
                <td class="col-fix"><div class="fix-box">$fix</div></td>
            </tr>
HTML
    }
    
    my $total_vulns = scalar(@$vulnerabilities);
    
    # Sort top rules for the bar chart
    my @top_rules = sort { $rule_counts{$b} <=> $rule_counts{$a} } keys %rule_counts;
    @top_rules = splice(@top_rules, 0, 5) if @top_rules > 5;
    
    my $max_rule_count = @top_rules ? $rule_counts{$top_rules[0]} : 1;
    $max_rule_count = 1 if $max_rule_count == 0;
    
    # Calculate security posture scores (0-100)
    my sub _calc_posture {
        my ($hits) = @_;
        return 100 if $hits == 0;
        my $res = 100 - ($hits * 14);
        return $res < 20 ? 20 : $res;
    }
    
    my $posture_injection    = _calc_posture($posture_hits{INJECTION});
    my $posture_exfiltration = _calc_posture($posture_hits{EXFILTRATION});
    my $posture_persistence  = _calc_posture($posture_hits{PERSISTENCE});
    my $posture_isolation    = _calc_posture($posture_hits{ISOLATION});
    my $posture_hygiene      = _calc_posture($posture_hits{HYGIENE});
    
    my $quality_score = $score_data->{quality_score} // 100;
    my $quality_grade = $score_data->{quality_grade} // 'A+';
    my $originality_score = $plagiarism_data->{summary}{originality_score} // 100;
    my $highest_plagiarism = $plagiarism_data->{summary}{highest_similarity} // 0;
    my $total_clones = $plagiarism_data->{summary}{total_clones} // 0;

    my $cat_class = lc($score_data->{category} || 'clean');
    my $score = $score_data->{score} || 0;
    my $category = uc($score_data->{category} || 'CLEAN');
    
    # Generate bar chart items HTML
    my @bar_palette = ('#f87171', '#60a5fa', '#4ade80', '#fbbf24', '#a78bfa');
    my $bar_items_html = '';
    for my $i (0 .. $#top_rules) {
        my $r = $top_rules[$i];
        my $val = $rule_counts{$r};
        my $color = $bar_palette[$i % @bar_palette];
        my $pct = int(($val / $max_rule_count) * 100);
        $pct = 15 if $pct < 15; # Minimum height for text
        $bar_items_html .= <<"HTML";
          <div class="bar-col group" data-idx="$i">
            <div class="bar-fill" style="height: ${pct}%; background-color: $color;" title="$r: $val occurrences">
              <div class="bar-texture"></div>
              <span class="bar-count">$val</span>
              <span class="bar-label">$r</span>
            </div>
            <div class="bar-tooltip">$r: $val hits</div>
          </div>
HTML
    }
    if (!@top_rules) {
        $bar_items_html = '<div class="no-findings-msg">✅ PERFECT! Zero rule violations or code errors detected.</div>';
    }

    # Generate Plagiarism Cards HTML
    my $clones_html = '';
    my $clone_list = $plagiarism_data->{clones} || [];
    for my $c_idx (0 .. $#{$clone_list}) {
        my $c = $clone_list->[$c_idx];
        my $sim = $c->{similarity};
        my $sim_class = $sim >= 80 ? 'sim-high' : ($sim >= 60 ? 'sim-med' : 'sim-low');
        my $sim_color = $sim >= 80 ? 'var(--critical)' : ($sim >= 60 ? 'var(--medium)' : 'var(--low)');
        my $file_a_base = basename($c->{file_a});
        my $file_b_base = basename($c->{file_b});
        my $snippet_a_esc = _escape_html($c->{snippet_a});
        my $snippet_b_esc = _escape_html($c->{snippet_b});

        $clones_html .= <<"HTML";
        <div class="clone-card">
            <div class="clone-header">
                <div class="clone-title-group">
                    <span class="clone-sim-badge" style="background: $sim_color; color: #fff;">$sim% MATCH</span>
                    <span class="clone-type-badge">$c->{clone_type}</span>
                    <span class="clone-files-text">
                        <strong>$file_a_base</strong> (L$c->{line_a_start}-L$c->{line_a_end})
                        <span class="clone-arrow">⟷</span>
                        <strong>$file_b_base</strong> (L$c->{line_b_start}-L$c->{line_b_end})
                    </span>
                </div>
                <button class="diff-toggle-btn" onclick="toggleCloneSnippet($c_idx, this)">Compare Snippets</button>
            </div>
            <div class="clone-diff-viewer hidden" id="cloneDiff$c_idx">
                <div class="diff-side">
                    <div class="diff-file-label">$c->{file_a} (Lines $c->{line_a_start}–$c->{line_a_end})</div>
                    <pre class="diff-code"><code>$snippet_a_esc</code></pre>
                </div>
                <div class="diff-side">
                    <div class="diff-file-label">$c->{file_b} (Lines $c->{line_b_start}–$c->{line_b_end})</div>
                    <pre class="diff-code"><code>$snippet_b_esc</code></pre>
                </div>
            </div>
        </div>
HTML
    }
    if (!@$clone_list) {
        $clones_html = '<div class="no-findings-msg">✅ 100% ORIGINAL! No code clones or duplicate fragments detected across files.</div>';
    }

    my $html = <<"HTML";
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security & Quality Audit Report | $metadata->{target_path}</title>
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@600;700;800;900&family=JetBrains+Mono:wght@500;700;800&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-page: #f4f4f5;
            --bg-card: #ffffff;
            --border-color: #000000;
            --shadow-color: rgba(0, 0, 0, 1);
            --text-primary: #000000;
            --text-secondary: #52525b;
            --dot-color: #000000;
            --card-hover-bg: #fafafa;
            --snippet-bg: #09090b;
            --snippet-text: #f4f4f5;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #22c55e;
            --accent: #a78bfa;
            --cyan: #06b6d4;
        }

        body.dark {
            --bg-page: #09090b;
            --bg-card: #18181b;
            --border-color: #ffffff;
            --shadow-color: rgba(255, 255, 255, 1);
            --text-primary: #ffffff;
            --text-secondary: #a1a1aa;
            --dot-color: #ffffff;
            --card-hover-bg: #27272a;
            --snippet-bg: #000000;
            --snippet-text: #e4e4e7;
        }

        * { box-sizing: border-box; }
        
        body {
            margin: 0;
            padding: 32px 16px;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background-color: var(--bg-page);
            color: var(--text-primary);
            background-image: radial-gradient(var(--dot-color) 1px, transparent 1px);
            background-size: 24px 24px;
            background-opacity: 0.05;
            transition: background-color 0.2s, color 0.2s;
            line-height: 1.5;
        }

        .container {
            max-width: 1440px;
            margin: 0 auto;
            position: relative;
            z-index: 10;
        }

        /* HEADER SECTION */
        .header-card {
            background-color: var(--bg-card);
            border: 3px solid var(--border-color);
            box-shadow: 8px 8px 0px 0px var(--shadow-color);
            padding: 28px 32px;
            margin-bottom: 28px;
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            align-items: center;
            gap: 24px;
            transition: all 0.2s;
        }

        .header-title-area h1 {
            font-family: 'Space Grotesk', sans-serif;
            font-size: clamp(2rem, 4vw, 3.2rem);
            font-weight: 900;
            text-transform: uppercase;
            letter-spacing: -0.04em;
            margin: 0 0 6px 0;
            line-height: 1;
        }

        .header-subtitle {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: var(--text-secondary);
        }

        .header-controls {
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
        }

        .meta-pill {
            background: var(--bg-card);
            border: 2px solid var(--border-color);
            padding: 8px 14px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            font-weight: 700;
            display: flex;
            flex-direction: column;
            box-shadow: 3px 3px 0 0 var(--shadow-color);
        }

        .meta-pill .label {
            font-size: 0.65rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .meta-pill .val {
            font-size: 1.1rem;
            font-weight: 900;
        }

        .theme-btn {
            background: var(--bg-card);
            border: 3px solid var(--border-color);
            box-shadow: 4px 4px 0px 0px var(--shadow-color);
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            font-weight: 900;
            padding: 10px 18px;
            cursor: pointer;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            transition: transform 0.1s, box-shadow 0.1s;
        }

        .theme-btn:hover {
            transform: translate(-2px, -2px);
            box-shadow: 6px 6px 0px 0px var(--shadow-color);
        }

        .theme-btn:active {
            transform: translate(2px, 2px);
            box-shadow: 2px 2px 0px 0px var(--shadow-color);
        }

        /* BENTO GRID */
        .bento-grid {
            display: grid;
            grid-template-columns: 1fr;
            gap: 24px;
            margin-bottom: 28px;
        }

        \@media (min-width: 1024px) {
            .bento-grid {
                grid-template-columns: 1fr 1fr;
            }
        }

        .bento-col {
            display: flex;
            flex-direction: column;
            gap: 24px;
        }

        .bento-card {
            background-color: var(--bg-card);
            border: 3px solid var(--border-color);
            box-shadow: 8px 8px 0px 0px var(--shadow-color);
            padding: 24px;
            position: relative;
            display: flex;
            flex-direction: column;
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 12px;
        }

        .card-title {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 1.25rem;
            font-weight: 800;
            margin: 0;
            display: flex;
            align-items: center;
            gap: 8px;
            text-transform: uppercase;
            letter-spacing: -0.02em;
        }

        .card-badge {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            font-weight: 800;
            padding: 4px 8px;
            border: 2px solid var(--border-color);
            background: var(--bg-page);
            box-shadow: 2px 2px 0 0 var(--shadow-color);
        }

        /* BAR CHART */
        .bar-chart-container {
            display: flex;
            align-items: flex-end;
            justify-content: space-around;
            height: 220px;
            padding: 10px 0;
            border-bottom: 2px solid var(--border-color);
            gap: 12px;
        }

        .bar-col {
            flex: 1;
            display: flex;
            flex-direction: column;
            align-items: center;
            height: 100%;
            justify-content: flex-end;
            position: relative;
        }

        .bar-fill {
            width: 100%;
            max-width: 50px;
            border: 3px solid var(--border-color);
            border-bottom: none;
            position: relative;
            transition: height 0.3s cubic-bezier(0.34, 1.56, 0.64, 1);
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            align-items: center;
            padding: 6px 2px;
            cursor: pointer;
        }

        .bar-count {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            font-weight: 900;
            color: #000;
        }

        .bar-label {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.7rem;
            font-weight: 800;
            color: #000;
            writing-mode: vertical-rl;
            transform: rotate(180deg);
        }

        .bar-tooltip {
            position: absolute;
            bottom: 100%;
            left: 50%;
            transform: translateX(-50%);
            background: var(--bg-card);
            border: 2px solid var(--border-color);
            padding: 4px 8px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            font-weight: 800;
            white-space: nowrap;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.15s, transform 0.15s;
            box-shadow: 4px 4px 0 0 var(--shadow-color);
            z-index: 20;
        }

        .bar-col:hover .bar-tooltip {
            opacity: 1;
            transform: translateX(-50%) translateY(-4px);
        }

        .no-findings-msg {
            width: 100%;
            text-align: center;
            padding: 40px;
            font-family: 'JetBrains Mono', monospace;
            font-weight: 700;
            font-size: 1.1rem;
            border: 2px dashed var(--border-color);
        }

        /* RADAR CHART */
        .radar-layout {
            display: flex;
            flex-direction: column;
            gap: 20px;
            flex: 1;
        }

        \@media (min-width: 640px) {
            .radar-layout {
                flex-direction: row;
                align-items: center;
            }
        }

        .radar-svg-box {
            flex: 1;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            min-height: 220px;
        }

        .radar-watermark {
            position: absolute;
            inset: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: 'Space Grotesk', sans-serif;
            font-size: 4rem;
            font-weight: 900;
            text-transform: uppercase;
            opacity: 0.05;
            pointer-events: none;
            letter-spacing: -0.05em;
        }

        .radar-stats-list {
            width: 100%;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        \@media (min-width: 640px) {
            .radar-stats-list {
                width: 200px;
            }
        }

        .radar-stat-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 5px 8px;
            border: 2px solid transparent;
            cursor: pointer;
            transition: all 0.2s;
            background: var(--bg-page);
        }

        .radar-stat-item:hover, .radar-stat-item.active {
            border-color: var(--border-color);
            transform: translateX(4px);
            box-shadow: 3px 3px 0 0 var(--shadow-color);
            background: var(--bg-card);
        }

        .radar-stat-label {
            display: flex;
            align-items: center;
            gap: 8px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.72rem;
            font-weight: 800;
        }

        .swatch {
            width: 10px;
            height: 10px;
            border: 2px solid var(--border-color);
            flex-shrink: 0;
        }

        .radar-stat-val {
            font-family: 'JetBrains Mono', monospace;
            font-weight: 900;
            font-size: 0.82rem;
        }

        /* DONUT CHART */
        .donut-wrapper {
            position: relative;
            width: 240px;
            height: 240px;
            margin: 10px auto;
        }

        \@media (min-width: 1200px) {
            .donut-wrapper {
                width: 260px;
                height: 260px;
            }
        }

        .donut-center-readout {
            position: absolute;
            inset: 0;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            pointer-events: none;
            text-align: center;
        }

        .donut-readout-val {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 2.6rem;
            font-weight: 900;
            line-height: 1;
            margin-bottom: 2px;
        }

        .donut-readout-label {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.7rem;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .donut-legend-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 8px;
            width: 100%;
            margin-top: 12px;
        }

        .legend-card {
            background: var(--bg-page);
            border: 2px solid var(--border-color);
            padding: 6px 10px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            box-shadow: 2px 2px 0 0 var(--shadow-color);
            cursor: pointer;
            transition: all 0.15s;
        }

        .legend-card:hover, .legend-card.active {
            transform: translate(-2px, -2px);
            box-shadow: 4px 4px 0 0 var(--shadow-color);
            background: var(--bg-card);
        }

        .legend-left {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .legend-title {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            font-weight: 800;
        }

        .legend-count {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            font-weight: 900;
        }

        /* PLAGIARISM SECTION */
        .plagiarism-panel {
            background-color: var(--bg-card);
            border: 3px solid var(--border-color);
            box-shadow: 8px 8px 0px 0px var(--shadow-color);
            padding: 24px;
            margin-bottom: 28px;
        }

        .clone-card {
            background: var(--bg-page);
            border: 2px solid var(--border-color);
            padding: 14px 18px;
            margin-bottom: 12px;
            box-shadow: 3px 3px 0 0 var(--shadow-color);
            transition: all 0.15s;
        }

        .clone-card:hover {
            box-shadow: 5px 5px 0 0 var(--shadow-color);
        }

        .clone-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
        }

        .clone-title-group {
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
        }

        .clone-sim-badge {
            font-family: 'JetBrains Mono', monospace;
            font-weight: 900;
            font-size: 0.8rem;
            padding: 3px 8px;
            border: 2px solid var(--border-color);
            box-shadow: 2px 2px 0 0 var(--shadow-color);
        }

        .clone-type-badge {
            font-family: 'JetBrains Mono', monospace;
            font-weight: 700;
            font-size: 0.75rem;
            padding: 3px 8px;
            background: var(--bg-card);
            border: 2px solid var(--border-color);
        }

        .clone-files-text {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.82rem;
        }

        .clone-arrow {
            color: var(--accent);
            font-weight: 900;
            padding: 0 4px;
        }

        .diff-toggle-btn {
            background: var(--bg-card);
            border: 2px solid var(--border-color);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            font-weight: 800;
            padding: 6px 12px;
            cursor: pointer;
            box-shadow: 2px 2px 0 0 var(--shadow-color);
            text-transform: uppercase;
        }

        .diff-toggle-btn:hover {
            background: var(--text-primary);
            color: var(--bg-card);
        }

        .clone-diff-viewer {
            display: grid;
            grid-template-columns: 1fr;
            gap: 16px;
            margin-top: 14px;
            padding-top: 14px;
            border-top: 2px dashed var(--border-color);
        }

        \@media (min-width: 768px) {
            .clone-diff-viewer {
                grid-template-columns: 1fr 1fr;
            }
        }

        .diff-side {
            background: var(--snippet-bg);
            color: var(--snippet-text);
            border: 2px solid var(--border-color);
            padding: 12px;
            border-radius: 2px;
        }

        .diff-file-label {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            font-weight: 700;
            color: #a1a1aa;
            margin-bottom: 8px;
            border-bottom: 1px solid #3f3f46;
            padding-bottom: 4px;
        }

        .diff-code {
            margin: 0;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            overflow-x: auto;
            white-space: pre-wrap;
            line-height: 1.4;
        }

        /* TABLE SECTION */
        .table-panel {
            background-color: var(--bg-card);
            border: 3px solid var(--border-color);
            box-shadow: 8px 8px 0px 0px var(--shadow-color);
            padding: 24px;
            margin-bottom: 28px;
        }

        .table-controls {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
            margin-bottom: 20px;
        }

        .filter-group {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
        }

        .filter-btn {
            background: var(--bg-page);
            border: 2px solid var(--border-color);
            padding: 6px 12px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            font-weight: 800;
            cursor: pointer;
            box-shadow: 2px 2px 0 0 var(--shadow-color);
            transition: all 0.15s;
            text-transform: uppercase;
        }

        .filter-btn:hover, .filter-btn.active {
            background: var(--text-primary);
            color: var(--bg-card);
            transform: translate(-1px, -1px);
            box-shadow: 3px 3px 0 0 var(--shadow-color);
        }

        .search-input {
            background: var(--bg-page);
            border: 2px solid var(--border-color);
            padding: 8px 14px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            font-weight: 700;
            color: var(--text-primary);
            box-shadow: 3px 3px 0 0 var(--shadow-color);
            outline: none;
            width: 240px;
            transition: width 0.2s;
        }

        .search-input:focus {
            width: 300px;
            border-color: var(--accent);
        }

        .table-responsive {
            width: 100%;
            overflow-x: auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-family: 'Inter', sans-serif;
            font-size: 0.85rem;
        }

        th {
            background: var(--bg-page);
            border: 2px solid var(--border-color);
            padding: 10px 12px;
            text-align: left;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        td {
            border: 2px solid var(--border-color);
            padding: 10px 12px;
            vertical-align: middle;
        }

        tr.vuln-row:hover td {
            background: var(--card-hover-bg);
        }

        .file-name {
            font-family: 'JetBrains Mono', monospace;
            font-weight: 800;
            display: block;
        }

        .line-badge {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.7rem;
            color: var(--text-secondary);
        }

        .rule-badge {
            font-family: 'JetBrains Mono', monospace;
            font-weight: 800;
            font-size: 0.75rem;
            padding: 2px 6px;
            background: var(--bg-page);
            border: 2px solid var(--border-color);
            display: inline-block;
        }

        .cwe-badge {
            font-family: 'JetBrains Mono', monospace;
            font-weight: 700;
            font-size: 0.65rem;
            padding: 2px 4px;
            background: var(--accent);
            color: #000;
            border: 1px solid var(--border-color);
            margin-left: 4px;
            display: inline-block;
        }

        .type-badge {
            font-family: 'JetBrains Mono', monospace;
            font-weight: 900;
            font-size: 0.7rem;
            padding: 3px 6px;
            border: 2px solid var(--border-color);
            box-shadow: 2px 2px 0 0 var(--shadow-color);
            text-transform: uppercase;
            display: inline-block;
        }

        .type-vulnerability { background: #fee2e2; color: #991b1b; }
        .type-error         { background: #fef3c7; color: #92400e; }
        .type-malware       { background: #fce7f3; color: #9d174d; }
        .type-secret        { background: #ede9fe; color: #5b21b6; }

        .sev-badge {
            font-family: 'JetBrains Mono', monospace;
            font-weight: 900;
            font-size: 0.75rem;
            padding: 3px 8px;
            border: 2px solid var(--border-color);
            box-shadow: 2px 2px 0 0 var(--shadow-color);
            text-transform: uppercase;
            display: inline-block;
        }

        .sev-critical { background: var(--critical); color: #fff; }
        .sev-high     { background: var(--high); color: #fff; }
        .sev-medium   { background: var(--medium); color: #000; }
        .sev-low      { background: var(--low); color: #000; }

        td.col-code code {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            background: var(--snippet-bg);
            color: var(--snippet-text);
            padding: 4px 8px;
            border-radius: 2px;
            display: block;
            max-width: 320px;
            overflow-x: auto;
            white-space: pre;
        }

        .fix-box {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            color: var(--low);
            background: rgba(34, 197, 94, 0.1);
            border-left: 3px solid var(--low);
            padding: 4px 8px;
        }

        /* PAGINATION CONTROLS */
        .pagination-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
            margin-top: 20px;
            padding-top: 18px;
            border-top: 2px solid var(--border-color);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
        }

        .pagination-info {
            color: var(--text-secondary);
            font-weight: 700;
        }

        .pagination-info strong, .pagination-info span {
            color: var(--text-primary);
            font-weight: 800;
        }

        .pagination-controls {
            display: flex;
            align-items: center;
            gap: 6px;
            flex-wrap: wrap;
        }

        .page-btn {
            background: var(--bg-page);
            border: 2px solid var(--border-color);
            padding: 6px 12px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            font-weight: 800;
            cursor: pointer;
            box-shadow: 2px 2px 0 0 var(--shadow-color);
            transition: all 0.15s ease;
            text-transform: uppercase;
            display: inline-flex;
            align-items: center;
            gap: 4px;
            color: var(--text-primary);
        }

        .page-btn:hover:not(:disabled) {
            background: var(--text-primary);
            color: var(--bg-card);
            transform: translate(-1px, -1px);
            box-shadow: 3px 3px 0 0 var(--shadow-color);
        }

        .page-btn.active {
            background: var(--accent);
            color: #000;
            border-color: var(--border-color);
            transform: translate(1px, 1px);
            box-shadow: 1px 1px 0 0 var(--shadow-color);
        }

        .page-btn:disabled {
            opacity: 0.35;
            cursor: not-allowed;
            box-shadow: none;
            transform: none;
        }

        .page-numbers {
            display: flex;
            align-items: center;
            gap: 4px;
        }

        .page-ellipsis {
            padding: 0 6px;
            color: var(--text-secondary);
            font-weight: 800;
            user-select: none;
        }

        /* COMPACT SLEEK FOOTER */
        .footer-card {
            background: var(--bg-card);
            border: 2px solid var(--border-color);
            box-shadow: 4px 4px 0px 0px var(--shadow-color);
            padding: 10px 18px;
            margin-top: 14px;
            margin-bottom: 24px;
            transition: all 0.15s ease;
        }

        .footer-card:hover {
            transform: translate(-1px, -1px);
            box-shadow: 5px 5px 0px 0px var(--shadow-color);
        }

        .footer-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
        }

        .footer-brand-link {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            text-decoration: none;
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            font-weight: 700;
            transition: all 0.15s ease;
            cursor: pointer;
        }

        .footer-brand-link:hover .footer-author-name {
            background: var(--text-primary);
            color: var(--bg-card);
            transform: translate(-1px, -1px);
            box-shadow: 3px 3px 0px 0px var(--shadow-color);
        }

        .footer-brand-link:hover .footer-logo-frame {
            transform: scale(1.08) rotate(-3deg);
            border-color: var(--accent);
        }

        .footer-logo-frame {
            width: 32px;
            height: 32px;
            background: #000000;
            border: 2px solid var(--border-color);
            box-shadow: 2px 2px 0px 0px var(--shadow-color);
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 4px;
            flex-shrink: 0;
            transition: all 0.2s ease;
        }

        .footer-logo-img {
            max-width: 100%;
            max-height: 100%;
            object-fit: contain;
            display: block;
        }

        .footer-created-text {
            color: var(--text-primary);
            letter-spacing: 0.02em;
        }

        .footer-author-name {
            font-weight: 900;
            background: var(--accent);
            color: #000000;
            padding: 2px 8px;
            border: 2px solid var(--border-color);
            box-shadow: 2px 2px 0px 0px var(--shadow-color);
            border-radius: 4px;
            letter-spacing: 0.04em;
            transition: all 0.15s ease;
            display: inline-block;
        }

        .footer-badges {
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }

        .footer-pill {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.72rem;
            font-weight: 700;
            padding: 4px 10px;
            background: var(--bg-page);
            border: 2px solid var(--border-color);
            color: var(--text-primary);
            box-shadow: 2px 2px 0px 0px var(--shadow-color);
        }

        .footer-dot {
            width: 7px;
            height: 7px;
            border-radius: 50%;
            background: #22c55e;
            box-shadow: 0 0 6px #22c55e;
            display: inline-block;
        }

        .hidden { display: none !important; }
    </style>
</head>
<body>
    <div class="container">
        <!-- HEADER -->
        <header class="header-card">
            <div class="header-title-area">
                <div style="display:flex; align-items:center; gap: 10px; margin-bottom: 6px;">
                    <span class="card-badge" style="background: var(--critical); color: #fff;">SECURITY &amp; QUALITY AUDIT</span>
                    <span class="header-subtitle">$metadata->{timestamp}</span>
                </div>
                <h1>Code Analyzer</h1>
                <div class="header-subtitle" style="display:flex; align-items:center; gap: 8px; margin-top: 4px;">
                    <span>TARGET:</span>
                    <span style="border-bottom: 2px solid var(--border-color); color: var(--text-primary);">$metadata->{target_path}</span>
                </div>
            </div>

            <div class="header-controls">
                <div class="meta-pill">
                    <span class="label">Files</span>
                    <span class="val">$metadata->{files_scanned}</span>
                </div>
                <div class="meta-pill">
                    <span class="label">LOC</span>
                    <span class="val">$metadata->{total_loc}</span>
                </div>
                <div class="meta-pill">
                    <span class="label">Vulns</span>
                    <span class="val" style="color: var(--critical);">$type_counts{vulnerability}</span>
                </div>
                <div class="meta-pill">
                    <span class="label">Code Errors</span>
                    <span class="val" style="color: var(--high);">$type_counts{error}</span>
                </div>
                <div class="meta-pill">
                    <span class="label">Max Plagiarism</span>
                    <span class="val" style="color: var(--accent);">$highest_plagiarism%</span>
                </div>
                <div class="meta-pill">
                    <span class="label">Quality</span>
                    <span class="val">$quality_grade ($quality_score%)</span>
                </div>
                <div class="meta-pill" style="border-color: var(--critical); color: var(--critical);">
                    <span class="label">Risk Category</span>
                    <span class="val">$category</span>
                </div>
                <button class="theme-btn" id="themeToggleBtn" onclick="toggleTheme()">Mode: Dark</button>
            </div>
        </header>

        <!-- MAIN BENTO GRID -->
        <div class="bento-grid">
            <!-- COLUMN 1: TOP RULES + SECURITY RADAR -->
            <div class="bento-col">
                <!-- CARD 1: TOP RULES (BRUTALIST BAR CHART) -->
                <div class="bento-card" style="min-height: 380px;">
                    <div class="card-header">
                        <h2 class="card-title">
                            <span>🔥</span> Top Violated Rules
                        </h2>
                        <span class="card-badge">Rule Hits</span>
                    </div>
                    <div class="bar-chart-container">
                        $bar_items_html
                    </div>
                </div>

                <!-- CARD 2: SECURITY & CODE POSTURE (BRUTALIST RADAR CHART) -->
                <div class="bento-card" style="min-height: 380px;">
                    <div class="card-header">
                        <h2 class="card-title">
                            <span>⚡</span> Defense &amp; Quality Posture
                        </h2>
                        <span class="card-badge">Health Metrics</span>
                    </div>
                    <div class="radar-layout">
                        <div class="radar-svg-box">
                            <div class="radar-watermark">AUDIT</div>
                            <svg id="radarSvg" viewBox="0 0 240 240" style="width: 100%; height: 100%; max-width: 250px; overflow: visible;"></svg>
                        </div>
                        <div class="radar-stats-list" id="radarList">
                            <!-- Populated via JS -->
                        </div>
                    </div>
                </div>
            </div>

            <!-- COLUMN 2: FULL HEIGHT THREAT & SEVERITY DONUT -->
            <div class="bento-col">
                <div class="bento-card" style="height: 100%; min-height: 520px; justify-content: space-between;">
                    <div class="card-header">
                        <h2 class="card-title">
                            <span>🛡️</span> Severity &amp; Threat Breakdown
                        </h2>
                        <span class="card-badge" style="background: var(--critical); color: #fff;">$total_vulns FINDINGS</span>
                    </div>

                    <div style="flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; position: relative;">
                        <div class="donut-wrapper">
                            <svg id="donutSvg" viewBox="-1.2 -1.2 2.4 2.4" style="width: 100%; height: 100%; transform: rotate(-90deg); overflow: visible;"></svg>
                            <div class="donut-center-readout">
                                <span class="donut-readout-val" id="donutVal">$score</span>
                                <span class="donut-readout-label" id="donutLabel">TOTAL RISK</span>
                            </div>
                        </div>

                        <div class="donut-legend-grid">
                            <div class="legend-card" data-sev="CRITICAL" onmouseenter="highlightDonut('CRITICAL')" onmouseleave="resetDonut()">
                                <div class="legend-left">
                                    <div class="swatch" style="background: var(--critical);"></div>
                                    <span class="legend-title">Critical</span>
                                </div>
                                <span class="legend-count">$counts{CRITICAL}</span>
                            </div>
                            <div class="legend-card" data-sev="HIGH" onmouseenter="highlightDonut('HIGH')" onmouseleave="resetDonut()">
                                <div class="legend-left">
                                    <div class="swatch" style="background: var(--high);"></div>
                                    <span class="legend-title">High</span>
                                </div>
                                <span class="legend-count">$counts{HIGH}</span>
                            </div>
                            <div class="legend-card" data-sev="MEDIUM" onmouseenter="highlightDonut('MEDIUM')" onmouseleave="resetDonut()">
                                <div class="legend-left">
                                    <div class="swatch" style="background: var(--medium);"></div>
                                    <span class="legend-title">Medium</span>
                                </div>
                                <span class="legend-count">$counts{MEDIUM}</span>
                            </div>
                            <div class="legend-card" data-sev="LOW" onmouseenter="highlightDonut('LOW')" onmouseleave="resetDonut()">
                                <div class="legend-left">
                                    <div class="swatch" style="background: var(--low);"></div>
                                    <span class="legend-title">Low</span>
                                </div>
                                <span class="legend-count">$counts{LOW}</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- 3. PLAGIARISM & CODE CLONES SECTION -->
        <section class="plagiarism-panel">
            <div class="card-header">
                <h2 class="card-title">
                    <span>🧬</span> Plagiarism &amp; Code Clone Intelligence
                </h2>
                <div style="display: flex; gap: 8px;">
                    <span class="card-badge" style="background: var(--accent); color: #000;">$total_clones Clones Found</span>
                    <span class="card-badge">Originality: $originality_score%</span>
                </div>
            </div>
            <div class="clones-container">
                $clones_html
            </div>
        </section>

        <!-- 4. FINDINGS TABLE -->
        <section class="table-panel">
            <div class="table-controls">
                <div>
                    <h2 class="card-title" style="font-size: 1.5rem; margin-bottom: 4px;">
                        <span>📋</span> Audit Findings ($total_vulns)
                    </h2>
                    <span class="header-subtitle" id="tableFilterStatus">Showing all records</span>
                </div>

                <div style="display: flex; gap: 12px; align-items: center; flex-wrap: wrap;">
                    <!-- Category Tabs -->
                    <div class="filter-group">
                        <button class="filter-btn active" onclick="filterCategory('all', this)">All ($total_vulns)</button>
                        <button class="filter-btn" onclick="filterCategory('vulnerability', this)">Vulns ($type_counts{vulnerability})</button>
                        <button class="filter-btn" onclick="filterCategory('error', this)">Code Errors ($type_counts{error})</button>
                        <button class="filter-btn" onclick="filterCategory('malware', this)">Malware ($type_counts{malware})</button>
                        <button class="filter-btn" onclick="filterCategory('secret', this)">Secrets ($type_counts{secret})</button>
                    </div>

                    <!-- Severity Filter -->
                    <div class="filter-group">
                        <button class="filter-btn active" onclick="filterSeverity('all', this)">All Sev</button>
                        <button class="filter-btn" onclick="filterSeverity('critical', this)">Critical</button>
                        <button class="filter-btn" onclick="filterSeverity('high', this)">High</button>
                        <button class="filter-btn" onclick="filterSeverity('medium', this)">Med</button>
                        <button class="filter-btn" onclick="filterSeverity('low', this)">Low</button>
                    </div>

                    <input type="text" id="searchInput" class="search-input" placeholder="🔍 Search findings..." oninput="handleSearch()">
                </div>
            </div>

            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th class="col-loc">Location</th>
                            <th class="col-type">Type</th>
                            <th class="col-rule">Rule &amp; CWE</th>
                            <th class="col-sev">Severity</th>
                            <th class="col-msg">Description</th>
                            <th class="col-code">Code Snippet</th>
                            <th class="col-fix">Remediation</th>
                        </tr>
                    </thead>
                    <tbody id="vulnTableBody">
                        $vuln_rows
                        <tr id="emptyTableRow" class="hidden">
                            <td colspan="7" style="text-align: center; padding: 36px; color: var(--text-secondary); font-family: 'JetBrains Mono', monospace; font-weight: 700;">
                                🚫 No audit findings match your selected filters.
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <!-- PAGINATION BAR (10 records per page) -->
            <div class="pagination-bar">
                <div class="pagination-info" id="paginationInfo">
                    Showing <strong id="pageStart">1</strong>–<strong id="pageEnd">10</strong> of <strong id="totalMatchingCount">0</strong> records
                </div>
                <div class="pagination-controls">
                    <button class="page-btn" id="firstPageBtn" onclick="goToPage(1)" title="First Page">« First</button>
                    <button class="page-btn" id="prevPageBtn" onclick="changePage(-1)" title="Previous Page">‹ Prev</button>
                    <div class="page-numbers" id="pageNumbers"></div>
                    <button class="page-btn" id="nextPageBtn" onclick="changePage(1)" title="Next Page">Next ›</button>
                    <button class="page-btn" id="lastPageBtn" onclick="goToLastPage()" title="Last Page">Last »</button>
                </div>
            </div>
        </section>

        <!-- COMPACT FOOTER WITH OMINDU D BRANDING & LOGO LINKED TO OMINDU.DEV -->
        <footer class="footer-card">
            <div class="footer-content">
                <a href="https://omindu.dev" target="_blank" rel="noopener noreferrer" class="footer-brand-link" title="Visit omindu.dev">
                    <div class="footer-logo-frame">
                        $logo_img_tag
                    </div>
                    <span class="footer-created-text">Created by</span>
                    <span class="footer-author-name">OminduD</span>
                </a>

                <div class="footer-badges">
                    <span class="footer-pill">
                        <span class="footer-dot"></span> Active Protection
                    </span>
                    <span class="footer-pill">
                        Automated Engine
                    </span>
                </div>
            </div>
        </footer>
    </div>

    <!-- CLIENT INTERACTIVITY & CHARTS SCRIPT -->
    <script>
        // 1. DATA FROM PERL
        const RADAR_DATA = [
            { label: "INJECTION", value: $posture_injection, color: "#f87171" },
            { label: "EXFILTRATION", value: $posture_exfiltration, color: "#fb923c" },
            { label: "PERSISTENCE", value: $posture_persistence, color: "#fbbf24" },
            { label: "ISOLATION", value: $posture_isolation, color: "#a78bfa" },
            { label: "QUALITY", value: $quality_score, color: "#38bdf8" },
            { label: "ORIGINALITY", value: $originality_score, color: "#4ade80" }
        ];

        const SEV_DATA = [
            { label: "CRITICAL", count: $counts{CRITICAL}, color: "#ef4444" },
            { label: "HIGH", count: $counts{HIGH}, color: "#f97316" },
            { label: "MEDIUM", count: $counts{MEDIUM}, color: "#eab308" },
            { label: "LOW", count: $counts{LOW}, color: "#22c55e" }
        ];

        const TOTAL_VULNS = $total_vulns;
        const TOTAL_SCORE = $score;

        // 2. THEME HANDLING
        function initTheme() {
            const saved = localStorage.getItem('pca_theme') || 'dark';
            if (saved === 'dark') {
                document.body.classList.add('dark');
                document.getElementById('themeToggleBtn').innerText = 'Mode: Light';
            } else {
                document.body.classList.remove('dark');
                document.getElementById('themeToggleBtn').innerText = 'Mode: Dark';
            }
        }

        function toggleTheme() {
            document.body.classList.toggle('dark');
            const isDark = document.body.classList.contains('dark');
            localStorage.setItem('pca_theme', isDark ? 'dark' : 'light');
            document.getElementById('themeToggleBtn').innerText = isDark ? 'Mode: Light' : 'Mode: Dark';
            renderRadar();
            renderDonut();
        }

        // 3. RADAR CHART
        const RADAR_SIZE = 240;
        const RADAR_CENTER = RADAR_SIZE / 2;
        const RADAR_RADIUS = 90;
        let activeRadarMetric = null;

        function angleToRad(angle) {
            return (Math.PI / 180) * angle;
        }

        function getRadarCoords(val, idx, total) {
            const angle = angleToRad((360 / total) * idx - 90);
            const r = (val / 100) * RADAR_RADIUS;
            return {
                x: RADAR_CENTER + r * Math.cos(angle),
                y: RADAR_CENTER + r * Math.sin(angle)
            };
        }

        function renderRadar() {
            const svg = document.getElementById('radarSvg');
            const list = document.getElementById('radarList');
            if (!svg || !list) return;

            const isDark = document.body.classList.contains('dark');
            const strokeColor = isDark ? '#ffffff' : '#000000';
            const gridColor = isDark ? 'rgba(255,255,255,0.15)' : 'rgba(0,0,0,0.15)';
            const total = RADAR_DATA.length;

            let svgContent = '';

            // Grid Levels (100, 75, 50, 25)
            [100, 75, 50, 25].forEach(level => {
                let path = '';
                for (let i = 0; i < total; i++) {
                    const c = getRadarCoords(level, i, total);
                    path += (i === 0 ? 'M ' : 'L ') + c.x + ' ' + c.y + ' ';
                }
                path += 'Z';
                svgContent += '<path d="' + path + '" fill="none" stroke="' + gridColor + '" stroke-width="2" stroke-dasharray="4 4" />';
            });

            // Axes lines
            for (let i = 0; i < total; i++) {
                const outer = getRadarCoords(100, i, total);
                svgContent += '<line x1="' + RADAR_CENTER + '" y1="' + RADAR_CENTER + '" x2="' + outer.x + '" y2="' + outer.y + '" stroke="' + gridColor + '" stroke-width="2" />';
            }

            // Data Polygon
            let polyPath = '';
            for (let i = 0; i < total; i++) {
                const c = getRadarCoords(RADAR_DATA[i].value, i, total);
                polyPath += (i === 0 ? 'M ' : 'L ') + c.x + ' ' + c.y + ' ';
            }
            polyPath += 'Z';
            svgContent += '<path d="' + polyPath + '" fill="rgba(167, 139, 250, 0.45)" stroke="' + strokeColor + '" stroke-width="3.5" stroke-linejoin="round" />';

            // Interactive points
            for (let i = 0; i < total; i++) {
                const item = RADAR_DATA[i];
                const c = getRadarCoords(item.value, i, total);
                const isHovered = activeRadarMetric === item.label;
                const r = isHovered ? 9 : 5.5;
                const fillColor = isHovered ? item.color : (isDark ? '#18181b' : '#ffffff');
                
                svgContent += '<g class="radar-dot-group" data-label="' + item.label + '" onmouseenter="hoverRadar(this.dataset.label)" onmouseleave="hoverRadar(null)" style="cursor: pointer;">';
                svgContent += '<circle cx="' + c.x + '" cy="' + c.y + '" r="18" fill="transparent" />';
                svgContent += '<circle cx="' + c.x + '" cy="' + c.y + '" r="' + r + '" fill="' + fillColor + '" stroke="' + strokeColor + '" stroke-width="3" style="transition: all 0.2s;" />';
                svgContent += '</g>';
            }

            svg.innerHTML = svgContent;

            // Render stats list
            let listContent = '';
            RADAR_DATA.forEach(d => {
                const isActive = activeRadarMetric === d.label;
                listContent += '<div class="radar-stat-item ' + (isActive ? 'active' : '') + '" data-label="' + d.label + '" onmouseenter="hoverRadar(this.dataset.label)" onmouseleave="hoverRadar(null)">';
                listContent += '  <div class="radar-stat-label">';
                listContent += '    <div class="swatch" style="background-color: ' + d.color + ';"></div>';
                listContent += '    <span>' + d.label + '</span>';
                listContent += '  </div>';
                listContent += '  <span class="radar-stat-val">' + d.value + '%</span>';
                listContent += '</div>';
            });
            list.innerHTML = listContent;
        }

        function hoverRadar(label) {
            activeRadarMetric = label;
            renderRadar();
        }

        // 4. DONUT CHART
        let activeDonutSev = null;

        function getPieCoords(percent) {
            const x = Math.cos(2 * Math.PI * percent);
            const y = Math.sin(2 * Math.PI * percent);
            return [x, y];
        }

        function renderDonut() {
            const svg = document.getElementById('donutSvg');
            if (!svg) return;

            const isDark = document.body.classList.contains('dark');
            const strokeColor = isDark ? '#ffffff' : '#000000';

            const activeSlices = SEV_DATA.filter(s => s.count > 0);
            const totalCount = activeSlices.reduce((acc, s) => acc + s.count, 0);

            let svgContent = '';
            let cumulativePercent = 0;

            if (totalCount === 0) {
                svgContent += '<circle cx="0" cy="0" r="1" fill="#22c55e" stroke="' + strokeColor + '" stroke-width="0.04" />';
            } else {
                activeSlices.forEach(slice => {
                    const slicePercent = slice.count / totalCount;
                    const startPercent = cumulativePercent;
                    const endPercent = cumulativePercent + slicePercent;
                    cumulativePercent = endPercent;

                    const [startX, startY] = getPieCoords(startPercent);
                    const [endX, endY] = getPieCoords(endPercent);
                    const largeArcFlag = slicePercent > 0.5 ? 1 : 0;

                    const isHovered = activeDonutSev === slice.label;
                    const isDimmed = activeDonutSev !== null && !isHovered;

                    let pathData = '';
                    if (slicePercent >= 0.999) {
                        pathData = 'M 1 0 A 1 1 0 1 1 -1 0 A 1 1 0 1 1 1 0 Z';
                    } else {
                        pathData = 'M ' + startX + ' ' + startY + ' A 1 1 0 ' + largeArcFlag + ' 1 ' + endX + ' ' + endY + ' L 0 0 Z';
                    }

                    const tx = isHovered ? (startX + endX) * 0.08 : 0;
                    const ty = isHovered ? (startY + endY) * 0.08 : 0;
                    const scale = isHovered ? 1.05 : 1;
                    const opacity = isDimmed ? 0.35 : 1;

                    svgContent += '<path d="' + pathData + '" fill="' + slice.color + '" stroke="' + strokeColor + '" stroke-width="0.04" stroke-linejoin="round" ';
                    svgContent += 'style="cursor: pointer; transform: translate(' + tx + 'px, ' + ty + 'px) scale(' + scale + '); opacity: ' + opacity + '; transition: transform 0.2s cubic-bezier(0.34, 1.56, 0.64, 1), opacity 0.2s;" ';
                    svgContent += 'data-sev="' + slice.label + '" onmouseenter="highlightDonut(this.dataset.sev)" onmouseleave="resetDonut()" />';
                });
            }

            const innerFill = isDark ? '#18181b' : '#ffffff';
            svgContent += '<circle cx="0" cy="0" r="0.56" fill="' + innerFill + '" stroke="' + strokeColor + '" stroke-width="0.04" />';

            svg.innerHTML = svgContent;
        }

        function highlightDonut(sev) {
            activeDonutSev = sev;
            const item = SEV_DATA.find(s => s.label === sev);
            const valEl = document.getElementById('donutVal');
            const labelEl = document.getElementById('donutLabel');
            if (item && valEl && labelEl) {
                const pct = TOTAL_VULNS > 0 ? Math.round((item.count / TOTAL_VULNS) * 100) : 0;
                valEl.innerText = item.count;
                valEl.style.color = item.color;
                labelEl.innerText = sev + ' (' + pct + '%)';
            }
            document.querySelectorAll('.legend-card').forEach(c => {
                c.classList.toggle('active', c.getAttribute('data-sev') === sev);
            });
            renderDonut();
        }

        function resetDonut() {
            activeDonutSev = null;
            const valEl = document.getElementById('donutVal');
            const labelEl = document.getElementById('donutLabel');
            if (valEl && labelEl) {
                valEl.innerText = TOTAL_SCORE;
                valEl.style.color = '';
                labelEl.innerText = 'TOTAL RISK';
            }
            document.querySelectorAll('.legend-card').forEach(c => c.classList.remove('active'));
            renderDonut();
        }

        // 5. PLAGIARISM SNIPPET TOGGLE
        function toggleCloneSnippet(idx, btn) {
            const viewer = document.getElementById('cloneDiff' + idx);
            if (!viewer) return;
            const isHidden = viewer.classList.contains('hidden');
            if (isHidden) {
                viewer.classList.remove('hidden');
                btn.innerText = 'Hide Snippets';
            } else {
                viewer.classList.add('hidden');
                btn.innerText = 'Compare Snippets';
            }
        }

        // 6. TABLE FILTERING, SEARCH & PAGINATION (10 RECORDS PER PAGE)
        const PAGE_SIZE = 10;
        let currentPage = 1;
        let currentSeverityFilter = 'all';
        let currentCategoryFilter = 'all';
        let matchingRows = [];

        function filterCategory(cat, btn) {
            currentCategoryFilter = cat;
            const group = btn.closest('.filter-group');
            if (group) {
                group.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
            }
            applyFilters();
        }

        function filterSeverity(sev, btn) {
            currentSeverityFilter = sev;
            const group = btn.closest('.filter-group');
            if (group) {
                group.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
            }
            applyFilters();
        }

        function handleSearch() {
            applyFilters();
        }

        function applyFilters() {
            const query = (document.getElementById('searchInput').value || '').toLowerCase().trim();
            const allRows = Array.from(document.querySelectorAll('.vuln-row'));

            matchingRows = allRows.filter(row => {
                const sev = row.getAttribute('data-severity');
                const type = row.getAttribute('data-type');
                const searchData = (row.getAttribute('data-search') || '').toLowerCase();

                const matchesSev = (currentSeverityFilter === 'all' || sev === currentSeverityFilter);
                const matchesCat = (currentCategoryFilter === 'all' || type === currentCategoryFilter);
                const matchesSearch = (!query || searchData.includes(query));

                return matchesSev && matchesCat && matchesSearch;
            });

            // Reset to page 1 whenever filter or search query changes
            currentPage = 1;
            renderPagination();
        }

        function renderPagination() {
            const totalRecords = matchingRows.length;
            const totalPages = Math.ceil(totalRecords / PAGE_SIZE) || 1;

            if (currentPage > totalPages) currentPage = totalPages;
            if (currentPage < 1) currentPage = 1;

            const startIndex = (currentPage - 1) * PAGE_SIZE;
            const endIndex = Math.min(startIndex + PAGE_SIZE, totalRecords);

            // Hide all rows first
            document.querySelectorAll('.vuln-row').forEach(r => r.classList.add('hidden'));

            // Show only the 10 rows for current page
            for (let i = startIndex; i < endIndex; i++) {
                matchingRows[i].classList.remove('hidden');
            }

            // Empty state row toggle
            const emptyRow = document.getElementById('emptyTableRow');
            if (emptyRow) {
                if (totalRecords === 0) {
                    emptyRow.classList.remove('hidden');
                } else {
                    emptyRow.classList.add('hidden');
                }
            }

            // Update record count labels
            const pageStartEl = document.getElementById('pageStart');
            const pageEndEl = document.getElementById('pageEnd');
            const totalCountEl = document.getElementById('totalMatchingCount');
            const tableStatusEl = document.getElementById('tableFilterStatus');

            if (totalRecords === 0) {
                if (pageStartEl) pageStartEl.innerText = '0';
                if (pageEndEl) pageEndEl.innerText = '0';
            } else {
                if (pageStartEl) pageStartEl.innerText = (startIndex + 1).toString();
                if (pageEndEl) pageEndEl.innerText = endIndex.toString();
            }
            if (totalCountEl) totalCountEl.innerText = totalRecords.toString();

            // Update status text
            const catText = currentCategoryFilter === 'all' ? 'All Types' : currentCategoryFilter.toUpperCase();
            const sevText = currentSeverityFilter === 'all' ? 'All Severities' : currentSeverityFilter.toUpperCase();
            if (tableStatusEl) {
                tableStatusEl.innerText = 'Filters: ' + catText + ' • ' + sevText + ' (Page ' + currentPage + ' of ' + totalPages + ')';
            }

            // Update navigation button states
            const firstBtn = document.getElementById('firstPageBtn');
            const prevBtn = document.getElementById('prevPageBtn');
            const nextBtn = document.getElementById('nextPageBtn');
            const lastBtn = document.getElementById('lastPageBtn');

            if (firstBtn) firstBtn.disabled = (currentPage <= 1);
            if (prevBtn) prevBtn.disabled = (currentPage <= 1);
            if (nextBtn) nextBtn.disabled = (currentPage >= totalPages);
            if (lastBtn) lastBtn.disabled = (currentPage >= totalPages);

            renderPageNumbers(totalPages);
        }

        function changePage(delta) {
            const totalPages = Math.ceil(matchingRows.length / PAGE_SIZE) || 1;
            const targetPage = currentPage + delta;
            if (targetPage >= 1 && targetPage <= totalPages) {
                currentPage = targetPage;
                renderPagination();
                const panel = document.querySelector('.table-panel');
                if (panel) {
                    panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            }
        }

        function goToPage(page) {
            const totalPages = Math.ceil(matchingRows.length / PAGE_SIZE) || 1;
            if (page >= 1 && page <= totalPages) {
                currentPage = page;
                renderPagination();
                const panel = document.querySelector('.table-panel');
                if (panel) {
                    panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            }
        }

        function goToLastPage() {
            const totalPages = Math.ceil(matchingRows.length / PAGE_SIZE) || 1;
            goToPage(totalPages);
        }

        function renderPageNumbers(totalPages) {
            const container = document.getElementById('pageNumbers');
            if (!container) return;
            container.innerHTML = '';

            if (totalPages <= 1) return;

            const pages = [];
            if (totalPages <= 7) {
                for (let i = 1; i <= totalPages; i++) pages.push(i);
            } else {
                pages.push(1);
                if (currentPage > 3) pages.push('...');
                
                const start = Math.max(2, currentPage - 1);
                const end = Math.min(totalPages - 1, currentPage + 1);
                for (let i = start; i <= end; i++) {
                    if (!pages.includes(i)) pages.push(i);
                }

                if (currentPage < totalPages - 2) pages.push('...');
                if (!pages.includes(totalPages)) pages.push(totalPages);
            }

            pages.forEach(p => {
                if (p === '...') {
                    const ellipsis = document.createElement('span');
                    ellipsis.className = 'page-ellipsis';
                    ellipsis.innerText = '…';
                    container.appendChild(ellipsis);
                } else {
                    const btn = document.createElement('button');
                    btn.className = 'page-btn' + (p === currentPage ? ' active' : '');
                    btn.innerText = p.toString();
                    btn.onclick = () => goToPage(p);
                    container.appendChild(btn);
                }
            });
        }

        // Initial setup on load
        function initDashboard() {
            initTheme();
            renderRadar();
            renderDonut();
            applyFilters();
        }

        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', initDashboard);
        } else {
            initDashboard();
        }
    </script>
</body>
</html>
HTML

    my $fh;
    unless (open $fh, '>', $output_file) {
        carp "Error: Could not open HTML report file '$output_file' for writing: $!\n";
        return;
    }
    print $fh $html;
    close $fh;
}

sub _escape_html {
    my ($text) = @_;
    return '' unless defined $text;
    $text =~ s/&/&amp;/g;
    $text =~ s/</&lt;/g;
    $text =~ s/>/&gt;/g;
    $text =~ s/"/&quot;/g;
    $text =~ s/'/&#39;/g;
    return $text;
}

1;
