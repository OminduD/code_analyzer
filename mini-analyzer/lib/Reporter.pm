package Reporter;

use strict;
use warnings;
use Term::ANSIColor;
use JSON::PP;
use File::Basename;

sub print_terminal {
    my ($vulnerabilities, $score_data) = @_;
    
    print "=== Perl Static Code Security Analyzer ===\n\n";
    
    my %color_map = (
        HIGH   => 'bold red',
        MEDIUM => 'bold yellow',
        LOW    => 'bold green',
    );
    
    if (!@$vulnerabilities) {
        print color('bold green'), "No vulnerabilities found!\n", color('reset');
    }
    
    foreach my $vuln (@$vulnerabilities) {
        my $sev = uc($vuln->{severity});
        my $color = $color_map{$sev} || 'reset';
        
        print color($color), "[$sev] ", color('reset');
        print color('bold white'), "$vuln->{file}:$vuln->{line}", color('reset'), " ";
        print "(Rule: $vuln->{rule_id})\n";
        print "  Message : $vuln->{message}\n";
        print "  Snippet : $vuln->{snippet}\n";
        print "  Fix     : $vuln->{fix}\n";
        print "-" x 60, "\n";
    }
    
    print "\n=== Risk Summary ===\n";
    print "Total Risk Score : $score_data->{score}\n";
    
    my $cat_color = $score_data->{category} eq 'CRITICAL' ? 'bold red' :
                    $score_data->{category} eq 'MODERATE' ? 'bold yellow' : 'bold green';
                    
    print "Risk Category    : ", color($cat_color), $score_data->{category}, color('reset'), "\n";
}

sub generate_json {
    my ($vulnerabilities, $score_data, $output_file) = @_;
    
    my %report = (
        summary => $score_data,
        vulnerabilities => $vulnerabilities,
    );
    
    my $json = JSON::PP->new->pretty->encode(\%report);
    
    open my $fh, '>', $output_file or die "Could not open $output_file for writing: $!\n";
    print $fh $json;
    close $fh;
    
    print "JSON report generated: $output_file\n";
}

sub generate_html {
    my ($vulnerabilities, $score_data, $output_file) = @_;
    
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
            <tr>
                <td title="$vuln->{file}">$file_name</td>
                <td>$vuln->{line}</td>
                <td>$vuln->{rule_id}</td>
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
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Analysis Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f4f6f9; color: #333; margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 2px solid #ecf0f1; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .summary { display: flex; gap: 20px; margin-bottom: 30px; flex-wrap: wrap; }
        .stat-box { background: #ecf0f1; padding: 20px; border-radius: 8px; flex: 1; text-align: center; min-width: 150px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
        .stat-box.score { font-size: 1.2em; font-weight: bold; background: #fff; border: 2px solid #bdc3c7; }
        .cat-critical { color: #e74c3c; }
        .cat-moderate { color: #f39c12; }
        .cat-low { color: #2ecc71; }
        .sev-high { color: white; background-color: #e74c3c; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 0.9em; display: inline-block; width: 60px; text-align: center; }
        .sev-medium { color: white; background-color: #e67e22; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 0.9em; display: inline-block; width: 60px; text-align: center; }
        .sev-low { color: white; background-color: #2ecc71; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 0.9em; display: inline-block; width: 60px; text-align: center; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        th, td { padding: 12px 15px; border-bottom: 1px solid #e0e0e0; text-align: left; }
        th { background: #2c3e50; color: white; font-weight: 600; text-transform: uppercase; font-size: 0.9em; }
        tr:nth-child(even) { background: #f8f9fa; }
        tr:hover { background: #f1f3f5; }
        code { background: #fdf6e3; padding: 4px 6px; border-radius: 4px; color: #d35400; font-family: Consolas, monospace; font-size: 0.95em; word-break: break-all; }
        .count { font-size: 2em; font-weight: bold; margin-top: 10px; display: block; }
        .count.high { color: #e74c3c; }
        .count.medium { color: #e67e22; }
        .count.low { color: #2ecc71; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Perl Static Code Security Analyzer</h1>
        
        <h2>Summary Statistics</h2>
        <div class="summary">
            <div class="stat-box score">
                Total Risk Score
                <span class="count cat-$cat_class">$score</span>
                <div style="margin-top: 5px; font-size: 0.8em; text-transform: uppercase; color: #7f8c8d;">Category: <strong class="cat-$cat_class">$category</strong></div>
            </div>
            <div class="stat-box">
                HIGH Vulnerabilities
                <span class="count high">$counts{HIGH}</span>
            </div>
            <div class="stat-box">
                MEDIUM Vulnerabilities
                <span class="count medium">$counts{MEDIUM}</span>
            </div>
            <div class="stat-box">
                LOW Vulnerabilities
                <span class="count low">$counts{LOW}</span>
            </div>
        </div>

        <h2>Vulnerabilities Detail</h2>
        <table>
            <tr>
                <th>File</th>
                <th>Line</th>
                <th>Rule ID</th>
                <th>Severity</th>
                <th>Message</th>
                <th>Code Snippet</th>
                <th>Suggested Fix</th>
            </tr>
            $vuln_rows
        </table>
        
        <div style="margin-top: 40px; text-align: center; color: #95a5a6; font-size: 0.9em;">
            Generated by Perl Static Code Security Analyzer
        </div>
    </div>
</body>
</html>
HTML

    open my $fh, '>', $output_file or die "Could not open $output_file for writing: $!\n";
    print $fh $html;
    close $fh;
    
    print "HTML report generated: $output_file\n";
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
