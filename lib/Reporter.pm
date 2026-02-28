package Reporter;

use strict;
use warnings;
use Term::ANSIColor;
use JSON::PP;
use File::Basename;

sub print_terminal {
    my ($vulnerabilities, $score_data, $metadata) = @_;
    
    print color('bold cyan'), "\n" . "=" x 60 . "\n";
    print " PERL STATIC CODE SECURITY ANALYZER\n";
    print "=" x 60 . "\n", color('reset');
    
    if ($metadata) {
        print color('bright_black');
        print " Date         : $metadata->{timestamp}\n";
        print " Target Path  : $metadata->{target_path}\n";
        print " Language     : " . uc($metadata->{language}) . "\n";
        print " Files Scanned: $metadata->{files_scanned}\n";
        print color('reset'), "-" x 60 . "\n\n";
    }
    
    my %color_map = (
        HIGH   => 'bold red',
        MEDIUM => 'bold yellow',
        LOW    => 'bold green',
    );
    
    if (!@$vulnerabilities) {
        print color('bold green'), " [V] No vulnerabilities found! Code looks clean.\n\n", color('reset');
    }
    
    foreach my $vuln (@$vulnerabilities) {
        my $sev = uc($vuln->{severity});
        my $cat_color = $color_map{$sev} || 'reset';
        
        print color($cat_color), " [$sev] ", color('reset');
        print color('bold white'), "$vuln->{file}:$vuln->{line}", color('reset');
        print color('bright_black'), " (Rule: $vuln->{rule_id})\n", color('reset');
        print "  | Message : $vuln->{message}\n";
        print "  | Snippet : ", color('bright_white'), "$vuln->{snippet}\n", color('reset');
        print "  | Fix     : ", color('bright_green'), "$vuln->{fix}\n", color('reset');
        print "-" x 60, "\n";
    }
    
    print "\n", color('bold cyan'), "=== Risk Summary ===", color('reset'), "\n";
    
    my $cat_color = $score_data->{category} eq 'CRITICAL' ? 'bold red' :
                    $score_data->{category} eq 'MODERATE' ? 'bold yellow' : 'bold green';
                    
    print " Total Risk Score : $score_data->{score}\n";
    print " Risk Category    : ", color($cat_color), $score_data->{category}, color('reset'), "\n\n";
}

sub generate_json {
    my ($vulnerabilities, $score_data, $metadata, $output_file) = @_;
    
    my %report = (
        metadata        => $metadata,
        summary         => $score_data,
        vulnerabilities => $vulnerabilities,
    );
    
    my $json = JSON::PP->new->pretty->encode(\%report);
    
    open my $fh, '>', $output_file or die "Could not open $output_file for writing: $!\n";
    print $fh $json;
    close $fh;
    
    print color('bright_black'), " JSON report generated: $output_file\n", color('reset');
}

sub generate_html {
    my ($vulnerabilities, $score_data, $metadata, $output_file) = @_;
    
    my $vuln_rows = '';
    my %counts = ( HIGH => 0, MEDIUM => 0, LOW => 0 );
    
    foreach my $vuln (@$vulnerabilities) {
        my $sev = uc($vuln->{severity});
        $counts{$sev}++;
        
        my $sev_class = lc($sev);
        my $file_name = basename($vuln->{file});
        
        # Escape HTML manually to avoid dependencies
        my $snippet = _escape_html($vuln->{snippet});
        my $message = _escape_html($vuln->{message});
        my $fix     = _escape_html($vuln->{fix});
        
        $vuln_rows .= <<"HTML";
            <tr class="vuln-row" data-severity="$sev_class">
                <td title="$vuln->{file}"><strong>$file_name</strong><br><span style="color:#7f8c8d; font-size:0.85em;">Line $vuln->{line}</span></td>
                <td><span class="rule-badge">$vuln->{rule_id}</span></td>
                <td><span class="sev-$sev_class">$sev</span></td>
                <td>$message</td>
                <td><code>$snippet</code></td>
                <td>$fix</td>
            </tr>
HTML
    }
    
    my $cat_class = lc($score_data->{category});
    my $score = $score_data->{score};
    my $category = $score_data->{category};
    
    my $html = <<"HTML";
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report | $metadata->{target_path}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #f3f4f6;
            --surface: #ffffff;
            --text-main: #1f2937;
            --text-muted: #6b7280;
            --border: #e5e7eb;
            --critical: #ef4444;       --critical-bg: #fef2f2;
            --high: #f97316;           --high-bg: #fff7ed;
            --moderate: #eab308;       --moderate-bg: #fefce8;
            --low: #22c55e;            --low-bg: #f0fdf4;
            --cyan: #06b6d4;
        }
        
        body { font-family: 'Inter', sans-serif; background: var(--bg-color); color: var(--text-main); margin: 0; padding: 40px 20px; }
        .container { max-width: 1400px; margin: auto; background: var(--surface); padding: 40px; border-radius: 12px; box-shadow: 0 10px 15px -3px rgba(0,0,0,0.05), 0 4px 6px -2px rgba(0,0,0,0.025); }
        
        /* Header */
        .header-section { display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 1px solid var(--border); padding-bottom: 24px; margin-bottom: 32px; }
        h1 { margin: 0 0 10px 0; font-size: 1.8rem; font-weight: 700; display: flex; align-items: center; gap: 12px; }
        .title-badge { background: var(--cyan); color: white; padding: 4px 10px; border-radius: 6px; font-size: 0.8rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;}
        .metadata-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; font-size: 0.9rem; color: var(--text-muted); background: #f8fafc; padding: 16px; border-radius: 8px; border: 1px solid var(--border); }
        .metadata-item span { font-weight: 600; color: var(--text-main); display: block; margin-top: 4px; }
        
        /* Summary Cards */
        h2 { font-size: 1.3rem; font-weight: 600; margin-bottom: 20px; color: var(--text-main); }
        .summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 24px; margin-bottom: 40px; }
        .stat-card { padding: 24px; border-radius: 12px; border: 1px solid var(--border); position: relative; overflow: hidden; transition: transform 0.2s, box-shadow 0.2s; cursor: pointer; background: var(--surface); }
        .stat-card:hover { transform: translateY(-3px); box-shadow: 0 10px 15px -3px rgba(0,0,0,0.1); }
        .stat-card.active { border-color: var(--text-main); box-shadow: 0 0 0 2px var(--text-main); }
        .card-label { font-size: 0.9rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }
        .card-value { font-size: 2.5rem; font-weight: 700; line-height: 1; }
        
        /* Category specific card styling */
        .card-score { background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%); border-bottom: 4px solid var(--text-muted); cursor: default; }
        .card-score:hover { transform: none; box-shadow: none; }
        .card-score.cat-critical { border-bottom-color: var(--critical); }
        .card-score.cat-critical .card-value { color: var(--critical); }
        .card-score.cat-moderate { border-bottom-color: var(--moderate); }
        .card-score.cat-moderate .card-value { color: var(--moderate); }
        
        .card-high { border-bottom: 4px solid var(--critical); }
        .card-high .card-value { color: var(--critical); }
        
        .card-medium { border-bottom: 4px solid var(--high); }
        .card-medium .card-value { color: var(--high); }
        
        .card-low { border-bottom: 4px solid var(--low); }
        .card-low .card-value { color: var(--low); }

        /* Table */
        .table-controls { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
        #filter-status { font-size: 0.9rem; font-weight: 500; color: var(--text-muted); background: #f3f4f6; padding: 6px 12px; border-radius: 20px; display: none; }
        .btn-clear { background: none; border: 1px solid var(--border); padding: 6px 16px; border-radius: 6px; cursor: pointer; font-size: 0.85rem; font-weight: 500; display: none; transition: background 0.2s;}
        .btn-clear:hover { background: #f3f4f6; }
        
        table { width: 100%; border-collapse: separate; border-spacing: 0; margin-top: 10px; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
        th, td { padding: 16px; text-align: left; }
        th { background: #f8fafc; color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 0.8rem; letter-spacing: 0.5px; border-bottom: 1px solid var(--border); }
        tr { border-bottom: 1px solid var(--border); background: var(--surface); transition: background 0.15s; }
        tr:last-child { border-bottom: none; }
        tr:hover { background: #f8fafc; }
        td { border-bottom: 1px solid var(--border); font-size: 0.95rem; }
        
        /* Badges & Code */
        .rule-badge { background: #e5e7eb; padding: 4px 8px; border-radius: 4px; font-family: 'JetBrains Mono', monospace; font-size: 0.85em; font-weight: 600; }
        .sev-high { color: var(--critical); background-color: var(--critical-bg); padding: 6px 12px; border-radius: 20px; font-weight: 700; font-size: 0.85em; display: inline-block; border: 1px solid rgba(239,68,68,0.2); }
        .sev-medium { color: var(--high); background-color: var(--high-bg); padding: 6px 12px; border-radius: 20px; font-weight: 700; font-size: 0.85em; display: inline-block; border: 1px solid rgba(249,115,22,0.2); }
        .sev-low { color: var(--low); background-color: var(--low-bg); padding: 6px 12px; border-radius: 20px; font-weight: 700; font-size: 0.85em; display: inline-block; border: 1px solid rgba(34,197,94,0.2); }
        
        code { background: #f8fafc; border: 1px solid #e2e8f0; padding: 8px 12px; border-radius: 6px; color: #0f172a; font-family: 'JetBrains Mono', monospace; font-size: 0.9em; word-break: break-all; display: block; max-width: 400px; white-space: pre-wrap; line-height: 1.4;}
        
        .footer { margin-top: 50px; text-align: center; color: var(--text-muted); font-size: 0.85em; border-top: 1px solid var(--border); padding-top: 24px; }
        
        /* Utilities */
        .hidden { display: none !important; }
    </style>
</head>
<body>
    <div class="container">
        
        <div class="header-section">
            <div>
                <h1>Perl Security Analyzer <span class="title-badge">$metadata->{language}</span></h1>
                <p style="color: var(--text-muted); margin: 0;">Static Code Analysis Output</p>
            </div>
            
            <div class="metadata-grid">
                <div class="metadata-item">Scanned Target<span>$metadata->{target_path}</span></div>
                <div class="metadata-item">Files Analyzed<span>$metadata->{files_scanned}</span></div>
                <div class="metadata-item" style="grid-column: span 2;">Scan Completed<span>$metadata->{timestamp}</span></div>
            </div>
        </div>
        
        <h2>Threat Summary</h2>
        <div class="summary">
            <div class="stat-card card-score cat-$cat_class">
                <div class="card-label">Total Risk Score</div>
                <div class="card-value">$score</div>
                <div style="margin-top: 12px; font-size: 0.85rem; font-weight: 600; text-transform: uppercase;">
                    Category: <span class="cat-$cat_class">$category</span>
                </div>
            </div>
            <div class="stat-card card-high" onclick="filterTable('high', this)">
                <div class="card-label">High Severity</div>
                <div class="card-value">$counts{HIGH}</div>
                <div style="margin-top: 12px; font-size: 0.8rem; color: var(--text-muted);">Click to filter</div>
            </div>
            <div class="stat-card card-medium" onclick="filterTable('medium', this)">
                <div class="card-label">Medium Severity</div>
                <div class="card-value">$counts{MEDIUM}</div>
                <div style="margin-top: 12px; font-size: 0.8rem; color: var(--text-muted);">Click to filter</div>
            </div>
            <div class="stat-card card-low" onclick="filterTable('low', this)">
                <div class="card-label">Low Severity</div>
                <div class="card-value">$counts{LOW}</div>
                <div style="margin-top: 12px; font-size: 0.8rem; color: var(--text-muted);">Click to filter</div>
            </div>
        </div>

        <div class="table-controls">
            <h2>Vulnerability Findings</h2>
            <div style="display:flex; align-items:center; gap: 16px;">
                <div id="filter-status"></div>
                <button class="btn-clear" id="btn-clear" onclick="clearFilter()">Clear Filter</button>
            </div>
        </div>
        
        <table>
            <thead>
                <tr>
                    <th style="width: 15%">Location</th>
                    <th style="width: 10%">Rule ID</th>
                    <th style="width: 10%">Severity</th>
                    <th style="width: 25%">Message</th>
                    <th style="width: 25%">Code Snippet</th>
                    <th style="width: 15%">Suggested Fix</th>
                </tr>
            </thead>
            <tbody>
                $vuln_rows
            </tbody>
        </table>
        
        <div class="footer">
            Generated automatically by Perl Static Code Security Analyzer.
        </div>
    </div>

    <script>
        function filterTable(severity, cardElement) {
            // UI Updates
            document.querySelectorAll('.stat-card').forEach(c => c.classList.remove('active'));
            cardElement.classList.add('active');
            
            document.getElementById('filter-status').style.display = 'block';
            document.getElementById('filter-status').innerHTML = 'Filtering by: <strong>' + severity.toUpperCase() + '</strong>';
            document.getElementById('btn-clear').style.display = 'block';

            // Filtering logic
            const rows = document.querySelectorAll('.vuln-row');
            rows.forEach(row => {
                if (row.getAttribute('data-severity') === severity) {
                    row.classList.remove('hidden');
                } else {
                    row.classList.add('hidden');
                }
            });
        }
        
        function clearFilter() {
            // UI Updates
            document.querySelectorAll('.stat-card').forEach(c => c.classList.remove('active'));
            document.getElementById('filter-status').style.display = 'none';
            document.getElementById('btn-clear').style.display = 'none';
            
            // Show all rows
            const rows = document.querySelectorAll('.vuln-row');
            rows.forEach(row => row.classList.remove('hidden'));
        }
    </script>
</body>
</html>
HTML

    open my $fh, '>', $output_file or die "Could not open $output_file for writing: $!\n";
    print $fh $html;
    close $fh;
    
    print color('bright_black'), " HTML report generated:  $output_file\n", color('reset');
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
