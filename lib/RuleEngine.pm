package RuleEngine;

use strict;
use warnings;
use File::Spec;

# Loads rules for a specific language
sub load_rules {
    my ($rules_dir, $lang) = @_;
    
    my $rule_file = File::Spec->catfile($rules_dir, "${lang}_rules.pl");
    
    die "Rule file not found: $rule_file\n" unless -f $rule_file;
    
    my $rules = do $rule_file;
    die "Could not load rules from $rule_file: $@\n" if $@;
    die "Rules must be an array reference in $rule_file\n" unless ref($rules) eq 'ARRAY';
    
    return $rules;
}

# Runs the rules against tokenized file content
sub analyze {
    my ($file, $tokens, $rules) = @_;
    
    my @vulnerabilities;
    
    foreach my $token (@$tokens) {
        my $content  = $token->{content};
        my $line_num = $token->{line_num};
        
        foreach my $rule (@$rules) {
            # Advanced rules using custom matching logic
            if ($rule->{match_func}) {
                # Execute the custom match subroutine.
                # The rule itself can track state across multiple calls.
                my $vuln = $rule->{match_func}->($file, $token, \@vulnerabilities);
                if ($vuln) {
                    push @vulnerabilities, $vuln;
                }
            } 
            # Standard regex pattern rules
            elsif ($rule->{pattern}) {
                my $pattern = $rule->{pattern};
                if ($content =~ /$pattern/) {
                    push @vulnerabilities, {
                        file     => $file,
                        line     => $line_num,
                        rule_id  => $rule->{id},
                        message  => $rule->{message},
                        severity => $rule->{severity},
                        fix      => $rule->{fix},
                        snippet  => $content,
                    };
                }
            }
        }
    }
    
    return \@vulnerabilities;
}

1;
