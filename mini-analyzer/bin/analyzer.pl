#!/usr/bin/env perl

use strict;
use warnings;
use Getopt::Long;
use File::Spec;
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
    die "Usage: $0 --path <dir> --lang <c|php|python> [--json report.json] [--html report.html] [--severity <LOW|MEDIUM|HIGH>]\n";
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

# 4. Calculate score
my $score_data = Scorer::calculate_score(\@all_vulnerabilities);

# 5. Output reports
Reporter::print_terminal(\@all_vulnerabilities, $score_data);

if ($json_out) {
    Reporter::generate_json(\@all_vulnerabilities, $score_data, $json_out);
}

if ($html_out) {
    Reporter::generate_html(\@all_vulnerabilities, $score_data, $html_out);
}

exit 0;
