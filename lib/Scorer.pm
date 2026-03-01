package Scorer;

use strict;
use warnings;
use Carp;

my %SEVERITY_WEIGHT = (
    HIGH   => 10,
    MEDIUM => 5,
    LOW    => 1,
);

sub calculate_score {
    my ($vulnerabilities) = @_;
    croak "Expected vulnerabilities array reference" unless ref($vulnerabilities) eq 'ARRAY';
    
    my $total_score = 0;
    
    foreach my $vuln (@$vulnerabilities) {
        my $severity = uc($vuln->{severity});
        $total_score += $SEVERITY_WEIGHT{$severity} || 0;
    }
    
    my $category;
    if ($total_score <= 10 && $total_score > 0) {
        $category = 'LOW';
    } elsif ($total_score <= 30 && $total_score > 10) {
        $category = 'MODERATE';
    } elsif ($total_score > 30) {
        $category = 'CRITICAL';
    } else {
        $category = 'LOW'; # Score is 0
    }
    
    return {
        score    => $total_score,
        category => $category,
    };
}

1;
