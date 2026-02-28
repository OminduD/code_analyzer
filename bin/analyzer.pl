#!/usr/bin/env perl

use strict;
use warnings;
use Getopt::Long;
use File::Spec;
use File::Basename;
use Cwd qw(abs_path);
use FindBin;
use lib "$FindBin::Bin/../lib";

use Scanner;
use Tokenizer;
use RuleEngine;
use Scorer;
use Reporter;

my $path;
my $lang;
my $json_out;
my $html_out;
my $severity_filter;

GetOptions(
    "path=s"     => \$path,
    "lang=s"     => \$lang,
    "json=s"     => \$json_out,
    "html=s"     => \$html_out,
    "severity=s" => \$severity_filter,
) or die "Error parsing command line arguments\n";

if (!$path || !$lang) {
    die "Usage: $0 --path <dir> --lang <c|cpp|php|python|js|java|rust|go|lua|asm|ada|cobol|pascal> [--json report.json] [--html report.html] [--severity <LOW|MEDIUM|HIGH>]\n";
}

# Determine rules directory
my $rules_dir = File::Spec->catdir($FindBin::Bin, '..', 'rules');

# 1. Discover target files
my $files = Scanner::scan_directory($path, $lang);

if (!@$files) {
    print "No files found for language '$lang' in '$path'.\n";
    exit 0;
}

print "Found " . scalar(@$files) . " file(s) to scan.\n";

# 2. Load rules
my $rules;
eval {
    $rules = RuleEngine::load_rules($rules_dir, $lang);
};
if ($@) {
    die "Error loading rules: $@\n";
}

# 3. Analyze each file
my @all_vulnerabilities;

foreach my $file (@$files) {
    # Tokenize file (reads lines, strips comments)
    my $tokens = Tokenizer::tokenize_file($file, $lang);
    
    # Analyze tokens
    my $vulns = RuleEngine::analyze($file, $tokens, $rules);
    
    push @all_vulnerabilities, @$vulns;
}

# Apply severity filter if specified
if ($severity_filter) {
    my $filter = uc($severity_filter);
    if ($filter eq 'HIGH' || $filter eq 'MEDIUM' || $filter eq 'LOW') {
        @all_vulnerabilities = grep { uc($_->{severity}) eq $filter } @all_vulnerabilities;
    } else {
        warn "Warning: Unknown severity filter '$severity_filter'. Ignored.\n";
    }
}

# Add Metadata payload
my %metadata = (
    timestamp     => scalar(localtime),
    files_scanned => scalar(@$files),
    target_path   => $path,
    language      => $lang,
);

# 4. Calculate score
my $score_data = Scorer::calculate_score(\@all_vulnerabilities);

# 5. Output reports
Reporter::print_terminal(\@all_vulnerabilities, $score_data, \%metadata);

if ($json_out) {
    Reporter::generate_json(\@all_vulnerabilities, $score_data, \%metadata, $json_out);
}

if ($html_out) {
    Reporter::generate_html(\@all_vulnerabilities, $score_data, \%metadata, $html_out);
    
    # Auto-serve the HTML report
    my $abs_html = abs_path($html_out);
    if ($abs_html && -f $abs_html) {
        my $report_dir  = dirname($abs_html);
        my $report_name = basename($abs_html);
        my $port = 8000;
        
        print "\n\033[1;36m[i] Starting local web server to display HTML report...\033[0m\n";
        print "\033[92m[✓] Report hosted at: http://localhost:$port/$report_name\033[0m\n\n";
        
        # Open browser natively across Linux/Mac
        if ($^O eq 'linux') {
            system("xdg-open 'http://localhost:$port/$report_name' >/dev/null 2>&1 &");
        } elsif ($^O eq 'darwin') {
            system("open 'http://localhost:$port/$report_name' >/dev/null 2>&1 &");
        }
        
        # Spawn the python server synchronously so the process stays alive
        system("python3 -m http.server $port --directory '$report_dir'");
    }
}

exit 0;
