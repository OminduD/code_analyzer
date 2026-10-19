package Scorer;

use strict;
use warnings;
use Carp;

my %SEVERITY_WEIGHT = (
    CRITICAL => 15,
    HIGH     => 10,
    MEDIUM   => 5,
    LOW      => 1,
    INFO     => 0,
);

sub calculate_score {
    my ($vulnerabilities, $plagiarism_data) = @_;
    croak "Expected vulnerabilities array reference" unless ref($vulnerabilities) eq 'ARRAY';
    
    my $total_score = 0;
    my %counts_by_type = (
        vulnerability => 0,
        error         => 0,
        malware       => 0,
        secret        => 0,
    );

    my %counts_by_sev = (
        CRITICAL => 0,
        HIGH     => 0,
        MEDIUM   => 0,
        LOW      => 0,
        INFO     => 0,
    );
    
    foreach my $vuln (@$vulnerabilities) {
        my $severity = uc($vuln->{severity} || 'LOW');
        $counts_by_sev{$severity}++;
        $total_score += $SEVERITY_WEIGHT{$severity} || 0;

        my $type = lc($vuln->{type} || 'vulnerability');
        $type = 'vulnerability' unless exists $counts_by_type{$type};
        $counts_by_type{$type}++;
    }
    
    my $category;
    if ($total_score > 30) {
        $category = 'CRITICAL';
    } elsif ($total_score > 10) {
        $category = 'MODERATE';
    } elsif ($total_score > 0) {
        $category = 'LOW';
    } else {
        $category = 'CLEAN';
    }

    # Code Quality Index (0 - 100)
    # Deductions: each error subtracts 4 points, high severity error subtracts 8 points
    my $quality_deduction = ($counts_by_type{error} * 5) + 
                            ($counts_by_sev{HIGH} * 4) + 
                            ($counts_by_sev{CRITICAL} * 8) + 
                            ($counts_by_sev{MEDIUM} * 2);
    my $quality_score = 100 - $quality_deduction;
    $quality_score = 15 if $quality_score < 15 && (@$vulnerabilities > 0);
    $quality_score = 100 if $quality_score > 100;
    $quality_score = 100 if @$vulnerabilities == 0;

    my $quality_grade = 'A+';
    if ($quality_score < 40) {
        $quality_grade = 'F';
    } elsif ($quality_score < 60) {
        $quality_grade = 'D';
    } elsif ($quality_score < 75) {
        $quality_grade = 'C';
    } elsif ($quality_score < 88) {
        $quality_grade = 'B';
    } elsif ($quality_score < 96) {
        $quality_grade = 'A';
    }

    my $originality_score = 100;
    if ($plagiarism_data && $plagiarism_data->{summary}) {
        $originality_score = $plagiarism_data->{summary}{originality_score} // 100;
    }
    
    return {
        score             => $total_score,
        category          => $category,
        quality_score     => int($quality_score),
        quality_grade     => $quality_grade,
        originality_score => $originality_score,
        by_type           => \%counts_by_type,
        by_severity       => \%counts_by_sev,
    };
}

1;
