#!/usr/bin/env perl

use strict;
use warnings;
use Getopt::Long;
use File::Spec;
use FindBin;
use Carp;
use lib "$FindBin::Bin/../lib";

use Scanner;
use Tokenizer;
use RuleEngine;
use Scorer;
use Reporter;
use PlagiarismDetector;
use Term::ANSIColor;

my $path;
my $lang;
my $json_out;
my $html_out;
my $severity_filter;
my $type_filter;
my $check_plagiarism = 1;
my $min_similarity = 50;
my $serve;

# Setup global error handler for uncaught exceptions
$SIG{__DIE__} = sub {
    my $error = shift;
    # Don't intercept errors if they're inside an eval
    return if $^S; 
    
    print color('bold bright_red'), "\n [FATAL ERROR] ", color('reset');
    print "$error\n";
    print color('bright_black'), " Execution aborted. Please check the logs or inputs.\n", color('reset');
    exit 1;
};

GetOptions(
    "path=s"             => \$path,
    "lang=s"             => \$lang,
    "json=s"             => \$json_out,
    "html=s"             => \$html_out,
    "severity=s"         => \$severity_filter,
    "type=s"             => \$type_filter,
    "plagiarism!"        => \$check_plagiarism,
    "min-similarity=i"   => \$min_similarity,
    "serve"              => \$serve,
) or croak "Error parsing command line arguments\n";

if (!$path || !$lang) {
    print color('bold bright_red'), "\n [ERROR] Missing required arguments.\n\n", color('reset');
    print " Usage: $0 --path <dir> --lang <all|c|cpp|php|python|js|java|rust|go|lua|asm|ada|cobol|pascal|ruby|csharp|r|swift|kotlin|typescript|scala|perl|bash|haskell|env|config|sql>\n";
    print "        [--json report.json] [--html report.html] [--severity <LOW|MEDIUM|HIGH>] [--type <all|vulnerability|error|malware|secret>]\n";
    print "        [--no-plagiarism] [--min-similarity <pct> (default: 50)] [--serve]\n\n";
    exit 1;
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

# 2. Load Universal Rules (Secrets + Malware/Trojan/Virus)
my @universal_rule_files = (
    File::Spec->catfile($rules_dir, "secrets_rules.pl"),
    File::Spec->catfile($rules_dir, "malware_rules.pl"),
);
my $universal_rules = [];
for my $ufile (@universal_rule_files) {
    next unless -f $ufile;
    my $loaded = do $ufile;
    if ($@) {
        warn "Warning: Could not compile universal rules from $ufile: $@\n";
    } elsif (!defined $loaded) {
        warn "Warning: Could not read universal rules from $ufile: $!\n";
    } elsif (ref($loaded) eq 'ARRAY') {
        push @$universal_rules, @$loaded;
    } else {
        carp "Warning: Universal rules must be an array reference in $ufile.\n";
    }
}

# 3. Analyze each file
my @all_vulnerabilities;
my %loaded_rules;
my $total_loc = 0;
my $start_time = time();

foreach my $file_meta (@$files) {
    my $file = $file_meta->{path};
    my $file_lang = $file_meta->{lang};

    # Lazy-load rules for this language
    if (!exists $loaded_rules{$file_lang}) {
        eval {
            $loaded_rules{$file_lang} = RuleEngine::load_rules($rules_dir, $file_lang);
        };
        if ($@) {
            carp "Warning: Error loading rules for $file_lang: $@\n";
            $loaded_rules{$file_lang} = [];
        }
    }

    my @combined_rules = (@{$loaded_rules{$file_lang}}, @$universal_rules);

    # Tokenize file
    my $tokens = Tokenizer::tokenize_file($file, $file_lang);
    $total_loc += scalar(@$tokens);
    
    # Analyze tokens
    my $vulns = RuleEngine::analyze($file, $tokens, \@combined_rules);
    
    push @all_vulnerabilities, @$vulns;
}

# 4. Plagiarism & Code Clone Tracking
my $plagiarism_data = {
    clones  => [],
    summary => {
        total_clones       => 0,
        highest_similarity => 0,
        originality_score  => 100,
        duplicated_loc     => 0,
        files_with_clones  => 0,
    }
};

if ($check_plagiarism && scalar(@$files) > 0) {
    print "Running plagiarism & code clone analysis...\n";
    $plagiarism_data = PlagiarismDetector::detect_clones($files, {
        min_similarity => $min_similarity,
    });
}

my $end_time = time();
my $duration = $end_time - $start_time;
$duration = 1 if $duration == 0; # Prevent 0s duration display

# Apply severity filter if specified
if ($severity_filter) {
    my $filter = uc($severity_filter);
    if ($filter eq 'HIGH' || $filter eq 'MEDIUM' || $filter eq 'LOW' || $filter eq 'CRITICAL') {
        @all_vulnerabilities = grep { uc($_->{severity} || '') eq $filter } @all_vulnerabilities;
    } else {
        carp "Warning: Unknown severity filter '$severity_filter'. Ignored.\n";
    }
}

# Apply type filter if specified (vulnerability, error, malware, secret)
if ($type_filter && lc($type_filter) ne 'all') {
    my $t_filter = lc($type_filter);
    @all_vulnerabilities = grep { lc($_->{type} || 'vulnerability') eq $t_filter } @all_vulnerabilities;
}

# Add Metadata payload
my %metadata = (
    timestamp     => scalar(localtime),
    files_scanned => scalar(@$files),
    target_path   => $path,
    language      => $lang,
    total_loc     => $total_loc,
    duration_secs => $duration,
);

# 5. Calculate scores and quality metrics
my $score_data = Scorer::calculate_score(\@all_vulnerabilities, $plagiarism_data);

# 6. Output reports
Reporter::print_terminal(\@all_vulnerabilities, $score_data, \%metadata, $plagiarism_data);

if ($json_out) {
    Reporter::generate_json(\@all_vulnerabilities, $score_data, \%metadata, $plagiarism_data, $json_out);
}

# Always generate HTML report
$html_out ||= "security_report.html";
Reporter::generate_html(\@all_vulnerabilities, $score_data, \%metadata, $plagiarism_data, $html_out);

my $abs_path = File::Spec->rel2abs($html_out);
print color('bold bright_green'), "\n 📊 Web Report Generated!\n", color('reset');
print " 🔗 Local File: ", color('bold underline cyan'), "file://$abs_path", color('reset'), "\n";

if ($serve) {
    print color('bold magenta'), "\n 🚀 Starting local Web Server...\n", color('reset');
    print color('bright_green'), " 🌐 Dashboard available at: ", color('bold underline cyan'), "http://localhost:8000/$html_out", color('reset'), "\n\n";
    print color('bright_black'), " Press Ctrl+C to stop the server.\n\n", color('reset');
    system("python3 -m http.server 8000");
} else {
    print color('bright_black'), "\n 💡 Tip: Use --serve to open the report via a local web server (Python).\n\n", color('reset');
}

exit 0;
