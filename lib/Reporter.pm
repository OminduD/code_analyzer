package Reporter;

use strict;
use warnings;
use Term::ANSIColor;
use JSON::PP;
use File::Basename;

sub print_terminal {
    my ($vulnerabilities, $score_data, $metadata) = @_;
    
    print color('bold cyan');
    print "\n";
    print " ╔══════════════════════════════════════════════════════════════╗\n";
    print " ║                                                              ║\n";
    print " ║           PERL STATIC CODE SECURITY ANALYZER                 ║\n";
    print " ║                  Advanced Analysis Tool                      ║\n";
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
        print " └──────────────────────────────────────────────────────────────┘\n\n";
        print color('reset');
    }
    
    my %color_map = (
        HIGH   => 'bold bright_red',
        MEDIUM => 'bold bright_yellow',
        LOW    => 'bold bright_green',
    );
    
    if (!@$vulnerabilities) {
        print color('bold bright_green'), " [OK] PERFECT. No vulnerabilities found! Code looks clean.\n\n", color('reset');
    }
    
    foreach my $vuln (@$vulnerabilities) {
        my $sev = uc($vuln->{severity});
        my $cat_color = $color_map{$sev} || 'reset';
        
        print color($cat_color), " > [$sev] ", color('reset');
        print color('bold white'), "$vuln->{file}:$vuln->{line}", color('reset');
        print color('bright_black'), " (Rule: $vuln->{rule_id})\n", color('reset');
        print "    ├─ Message : $vuln->{message}\n";
        print "    ├─ Snippet : ", color('bright_red'), "$vuln->{snippet}\n", color('reset');
        print "    └─ Fix     : ", color('bright_green'), "$vuln->{fix}\n", color('reset');
        print "\n";
    }
    
    print "\n", color('bold cyan'), " ╭── Risk Summary ──────────────────────────╮", color('reset'), "\n";
    
    my $cat_color = $score_data->{category} eq 'CRITICAL' ? 'bold bright_red' :
                    $score_data->{category} eq 'MODERATE' ? 'bold bright_yellow' : 'bold bright_green';
                    
    printf(" │  Total Risk Score : %-20s │\n", $score_data->{score});
    print  " │  Risk Category    : ";
    print color($cat_color), sprintf("%-20s", $score_data->{category}), color('reset'), " │\n";
    print color('bold cyan'), " ╰──────────────────────────────────────────╯", color('reset'), "\n\n";
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
    
    print color('bright_black'), " [OK] JSON report generated: $output_file\n", color('reset');
}

sub generate_html {
    my ($vulnerabilities, $score_data, $metadata, $output_file) = @_;
    
    my $vuln_rows = '';
    my %counts = ( HIGH => 0, MEDIUM => 0, LOW => 0 );
    my %rule_counts;
    my %file_counts;
    
    foreach my $vuln (@$vulnerabilities) {
        my $sev = uc($vuln->{severity});
        $counts{$sev}++;
        
        my $rule = $vuln->{rule_id};
        $rule_counts{$rule}++;
        
        my $sev_class = lc($sev);
        my $file_name = basename($vuln->{file});
        $file_counts{$file_name}++;
        
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
    
    # Sort top rules for the bar chart
    my @top_rules = sort { $rule_counts{$b} <=> $rule_counts{$a} } keys %rule_counts;
    @top_rules = splice(@top_rules, 0, 5) if @top_rules > 5; # Get top 5
    
    my $top_rules_labels = "[" . join(",", map { "'$_'" } @top_rules) . "]";
    my $top_rules_data   = "[" . join(",", map { $rule_counts{$_} } @top_rules) . "]";

    # Sort top vulnerable files
    my @top_files = sort { $file_counts{$b} <=> $file_counts{$a} } keys %file_counts;
    @top_files = splice(@top_files, 0, 5) if @top_files > 5;
    
    my $top_files_labels = "[" . join(",", map { "'$_'" } @top_files) . "]";
    my $top_files_data   = "[" . join(",", map { $file_counts{$_} } @top_files) . "]";

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
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #f8fafc;
            --surface: #ffffff;
            --surface-hover: #f1f5f9;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --border: #e2e8f0;
            --critical: #ef4444;       --critical-bg: rgba(239, 68, 68, 0.1);
            --high: #f97316;           --high-bg: rgba(249, 115, 22, 0.1);
            --moderate: #eab308;       --moderate-bg: rgba(234, 179, 8, 0.1);
            --low: #10b981;            --low-bg: rgba(16, 185, 129, 0.1);
            --cyan: #0ea5e9;           --cyan-bg: rgba(14, 165, 233, 0.1);
        }
        
        body { font-family: 'Inter', system-ui, sans-serif; background: var(--bg-color); color: var(--text-main); margin: 0; padding: 40px 20px; line-height: 1.6; }
        .container { max-width: 1400px; margin: auto; }
        
        /* Header */
        .header-section { background: var(--surface); padding: 36px; border-radius: 16px; border: 1px solid var(--border); display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 32px; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.05), 0 8px 10px -6px rgba(0, 0, 0, 0.01); }
        h1 { margin: 0 0 12px 0; font-size: 2.2rem; font-weight: 800; display: flex; align-items: center; gap: 16px; color: #1e293b; letter-spacing: -0.02em; }
        .title-badge { background: var(--cyan); color: white; padding: 6px 12px; border-radius: 8px; font-size: 0.9rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; box-shadow: 0 4px 12px rgba(14, 165, 233, 0.3); }
        .metadata-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; font-size: 0.95rem; color: var(--text-muted); background: var(--bg-color); padding: 20px; border-radius: 12px; border: 1px solid var(--border); }
        .metadata-item span { font-weight: 700; color: var(--text-main); display: block; margin-top: 6px; font-size: 1.05rem; }
        
        /* Analytics Layout */
        .analytics-grid { display: grid; grid-template-columns: 1fr 3fr; gap: 32px; margin-bottom: 32px; }
        
        /* Summary Dashboard */
        .dashboard-panel { background: var(--surface); border: 1px solid var(--border); border-radius: 16px; padding: 32px 24px; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.05); }
        .dashboard-panel h2 { font-size: 1.25rem; font-weight: 700; color: #1e293b; margin-top: 0; margin-bottom: 24px; border-bottom: 2px solid var(--border); padding-bottom: 12px; }
        
        .score-display { text-align: center; margin-bottom: 40px; }
        .score-value { font-size: 4.5rem; font-weight: 900; line-height: 1; margin: 16px 0; letter-spacing: -0.03em; }
        .cat-critical { color: var(--critical); }
        .cat-moderate { color: var(--moderate); }
        .cat-low { color: var(--low); }
        
        /* Stats Grid */
        .stats-grid { display: grid; grid-template-columns: 1fr; gap: 16px; }
        .stat-card { display: flex; justify-content: space-between; align-items: center; padding: 20px; border-radius: 12px; border: 1px solid var(--border); background: var(--surface); cursor: pointer; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); box-shadow: 0 2px 4px rgba(0,0,0,0.02); }
        .stat-card:hover { transform: translateY(-4px); box-shadow: 0 10px 20px rgba(0,0,0,0.06); }
        .stat-card.active { border-color: var(--cyan); box-shadow: 0 0 0 2px var(--cyan); background: var(--cyan-bg); }
        .card-label { font-size: 0.95rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }
        .card-value { font-size: 1.75rem; font-weight: 800; }
        
        .stat-high { border-left: 5px solid var(--critical); }
        .stat-high .card-value { color: var(--critical); }
        
        .stat-medium { border-left: 5px solid var(--high); }
        .stat-medium .card-value { color: var(--high); }
        
        .stat-low { border-left: 5px solid var(--low); }
        .stat-low .card-value { color: var(--low); }
        
        /* Chart container */
        .charts-container { display: grid; grid-template-columns: repeat(3, 1fr); gap: 24px; }
        .chart-box { background: var(--surface); border: 1px solid var(--border); border-radius: 16px; padding: 24px; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.05); display: flex; flex-direction: column; transition: transform 0.3s ease; }
        .chart-box:hover { transform: translateY(-4px); }
        .chart-box h3 { font-size: 1.05rem; color: #1e293b; margin: 0 0 20px 0; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
        .chart-wrapper { position: relative; height: 260px; width: 100%; flex-grow: 1; display:flex; justify-content:center; align-items:center; }
        
        /* Table */
        .table-panel { background: var(--surface); border: 1px solid var(--border); border-radius: 16px; padding: 32px; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.05); }
        .table-controls { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
        .table-controls h2 { font-size: 1.5rem; font-weight: 800; margin: 0; color: #1e293b; }
        #filter-status { font-size: 0.95rem; font-weight: 600; color: var(--cyan); background: var(--cyan-bg); border: 1px solid rgba(14, 165, 233, 0.3); padding: 10px 20px; border-radius: 24px; display: none; }
        .btn-clear { background: white; border: 1px solid var(--border); color: var(--text-main); padding: 10px 20px; border-radius: 8px; cursor: pointer; font-size: 0.9rem; font-weight: 600; display: none; transition: all 0.2s; box-shadow: 0 2px 4px rgba(0,0,0,0.02);}
        .btn-clear:hover { background: var(--surface-hover); color: var(--critical); border-color: rgba(239, 68, 68, 0.3); }
        
        table { width: 100%; border-collapse: separate; border-spacing: 0; border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
        th, td { padding: 20px 24px; text-align: left; }
        th { background: var(--bg-color); color: var(--text-muted); font-weight: 700; text-transform: uppercase; font-size: 0.85rem; letter-spacing: 0.5px; border-bottom: 2px solid var(--border); }
        tr { border-bottom: 1px solid var(--border); background: var(--surface); transition: background 0.2s ease; }
        tr:last-child { border-bottom: none; }
        tr:hover { background: var(--surface-hover); }
        td { border-bottom: 1px solid var(--border); font-size: 0.95rem; }
        
        /* Badges & Code */
        .rule-badge { background: var(--bg-color); padding: 6px 10px; border-radius: 6px; font-family: 'JetBrains Mono', monospace; font-size: 0.85em; font-weight: 700; color: #475569; border: 1px solid var(--border); }
        .sev-high { color: var(--critical); background-color: var(--critical-bg); padding: 6px 14px; border-radius: 20px; font-weight: 700; font-size: 0.85em; display: inline-block; border: 1px solid rgba(239,68,68,0.2); }
        .sev-medium { color: var(--high); background-color: var(--high-bg); padding: 6px 14px; border-radius: 20px; font-weight: 700; font-size: 0.85em; display: inline-block; border: 1px solid rgba(249,115,22,0.2); }
        .sev-low { color: var(--low); background-color: var(--low-bg); padding: 6px 14px; border-radius: 20px; font-weight: 700; font-size: 0.85em; display: inline-block; border: 1px solid rgba(16,185,129,0.2); }
        
        code { background: var(--bg-color); border: 1px solid var(--border); padding: 12px 16px; border-radius: 8px; color: #334155; font-family: 'JetBrains Mono', monospace; font-size: 0.9em; word-break: break-all; display: block; max-width: 450px; white-space: pre-wrap; line-height: 1.5; box-shadow: inset 0 2px 4px rgba(0,0,0,0.02); }
        
        .footer { margin-top: 48px; text-align: center; color: var(--text-muted); font-size: 0.9em; font-weight: 500; }
        .hidden { display: none !important; }
    </style>
</head>
<body>
    <div class="container">
        
        <div class="header-section">
            <div>
                <h1>Perl Security Analyzer <span class="title-badge">$metadata->{language}</span></h1>
                <p style="color: var(--text-muted); margin: 0;">Advanced Static Code Analysis Output</p>
            </div>
            
            <div class="metadata-grid">
                <div class="metadata-item">Target Context<span>$metadata->{target_path}</span></div>
                <div class="metadata-item">Files Processed<span>$metadata->{files_scanned}</span></div>
                <div class="metadata-item">Lines of Code<span>$metadata->{total_loc}</span></div>
                <div class="metadata-item">Scan Duration<span>$metadata->{duration_secs}s</span></div>
                <div class="metadata-item" style="grid-column: span 2;">Analysis Timestamp<span>$metadata->{timestamp}</span></div>
            </div>
        </div>
        
        <div class="analytics-grid">
            <!-- Left Panel: Summary Stats -->
            <div class="dashboard-panel">
                <h2>Threat Assessment</h2>
                <div class="score-display">
                    <div style="font-size: 0.9rem; color: var(--text-muted); text-transform: uppercase;">Total Risk Score</div>
                    <div class="score-value cat-$cat_class">$score</div>
                    <div style="font-size: 0.95rem; font-weight: 600; text-transform: uppercase;" class="cat-$cat_class">$category RISK</div>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card stat-high" onclick="filterTable('high', this)">
                        <div class="card-label">High</div>
                        <div class="card-value">$counts{HIGH}</div>
                    </div>
                    <div class="stat-card stat-medium" onclick="filterTable('medium', this)">
                        <div class="card-label">Medium</div>
                        <div class="card-value">$counts{MEDIUM}</div>
                    </div>
                    <div class="stat-card stat-low" onclick="filterTable('low', this)">
                        <div class="card-label">Low</div>
                        <div class="card-value">$counts{LOW}</div>
                    </div>
                </div>
                <div style="text-align:center; font-size: 0.8rem; color: var(--text-muted); margin-top: 16px;">Click to filter findings</div>
            </div>
            
            <!-- Right Panel: Charts -->
            <div class="charts-container">
                <div class="chart-box">
                    <h3>Severity Distribution</h3>
                    <div class="chart-wrapper">
                        <canvas id="severityChart"></canvas>
                    </div>
                </div>
                <div class="chart-box">
                    <h3>Top Active Rules</h3>
                    <div class="chart-wrapper">
                        <canvas id="rulesChart"></canvas>
                    </div>
                </div>
                <div class="chart-box">
                    <h3>Top Vulnerable Files</h3>
                    <div class="chart-wrapper">
                        <canvas id="filesChart"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <div class="table-panel">
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
        </div>
        
        <div class="footer">
            Generated autonomously by Perl Static Code Security Analyzer
        </div>
    </div>

    <script>
        // Data populated from Perl
        const severityData = [$counts{HIGH}, $counts{MEDIUM}, $counts{LOW}];
        const ruleLabels = $top_rules_labels;
        const ruleData = $top_rules_data;
        const fileLabels = $top_files_labels;
        const fileData = $top_files_data;
        
        // Setup Chart defaults
        Chart.defaults.color = '#64748b';
        Chart.defaults.font.family = "'Inter', system-ui, sans-serif";
        
        // 1. Severity Doughnut Chart
        const ctxSev = document.getElementById('severityChart').getContext('2d');
        new Chart(ctxSev, {
            type: 'doughnut',
            data: {
                labels: ['High', 'Medium', 'Low'],
                datasets: [{
                    data: severityData,
                    backgroundColor: [
                        '#ef4444', // High
                        '#f97316', // Medium
                        '#22c55e'  // Low
                    ],
                    borderWidth: 0,
                    hoverOffset: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '70%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { padding: 20, usePointStyle: true, boxWidth: 8 }
                    },
                    tooltip: {
                        backgroundColor: '#ffffff',
                        titleColor: '#0f172a',
                        bodyColor: '#475569',
                        borderColor: '#e2e8f0',
                        borderWidth: 1,
                        padding: 12,
                        boxPadding: 6,
                        usePointStyle: true,
                    }
                }
            }
        });

        // 2. Top Rules Bar Chart
        const ctxRules = document.getElementById('rulesChart').getContext('2d');
        new Chart(ctxRules, {
            type: 'bar',
            data: {
                labels: ruleLabels,
                datasets: [{
                    label: 'Occurrences',
                    data: ruleData,
                    backgroundColor: '#0ea5e9',
                    borderRadius: 4,
                    barThickness: 'flex',
                    maxBarThickness: 40
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: '#ffffff',
                        titleColor: '#0f172a',
                        bodyColor: '#475569',
                        borderColor: '#e2e8f0',
                        borderWidth: 1,
                        padding: 12
                    }
                },
                scales: {
                    x: {
                        grid: { display: false, drawBorder: false },
                        ticks: { font: { family: "'JetBrains Mono', monospace", size: 10 }, color: '#64748b' }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(0, 0, 0, 0.05)', drawBorder: false },
                        ticks: { stepSize: 1, precision: 0, color: '#64748b' }
                    }
                }
            }
        });

        // 3. Top Files Bar Chart
        const ctxFiles = document.getElementById('filesChart').getContext('2d');
        new Chart(ctxFiles, {
            type: 'bar',
            data: {
                labels: fileLabels,
                datasets: [{
                    label: 'Vulnerabilities',
                    data: fileData,
                    backgroundColor: '#eab308',
                    borderRadius: 4,
                    barThickness: 'flex',
                    maxBarThickness: 40
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: '#ffffff',
                        titleColor: '#0f172a',
                        bodyColor: '#475569',
                        borderColor: '#e2e8f0',
                        borderWidth: 1,
                        padding: 12
                    }
                },
                scales: {
                    x: {
                        grid: { display: false, drawBorder: false },
                        ticks: { font: { family: "'JetBrains Mono', monospace", size: 10 }, color: '#64748b' }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(0, 0, 0, 0.05)', drawBorder: false },
                        ticks: { stepSize: 1, precision: 0, color: '#64748b' }
                    }
                }
            }
        });

        // Filtering logic
        function filterTable(severity, cardElement) {
            document.querySelectorAll('.stat-card').forEach(c => c.classList.remove('active'));
            cardElement.classList.add('active');
            
            document.getElementById('filter-status').style.display = 'block';
            document.getElementById('filter-status').innerHTML = 'Filtering by: <strong>' + severity.toUpperCase() + '</strong>';
            document.getElementById('btn-clear').style.display = 'block';

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
            document.querySelectorAll('.stat-card').forEach(c => c.classList.remove('active'));
            document.getElementById('filter-status').style.display = 'none';
            document.getElementById('btn-clear').style.display = 'none';
            
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
