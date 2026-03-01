package RuleEngine;

use strict;
use warnings;
use File::Spec;

# Loads rules for a specific language
sub load_rules {
    my ($rules_dir, $lang) = @_;
    
    my $rule_file = File::Spec->catfile($rules_dir, "${lang}_rules.pl");
    
    if (!-f $rule_file) {
        # Return empty ruleset instead of dying, useful for 'all' mode where 
        # a file extension might be recognized but no rules defined yet.
        return [];
    }
    
    my $rules = do $rule_file;
    if ($@) {
        warn "Error compiling rules from $rule_file: $@\n";
        return [];
    } elsif (!defined $rules) {
        warn "Error reading rules from $rule_file: $!\n";
        return [];
    }
    
    if (ref($rules) ne 'ARRAY') {
        warn "Rules must be an array reference in $rule_file\n";
        return [];
    }
    
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
                eval {
                    my $vuln = $rule->{match_func}->($file, $token, \@vulnerabilities);
                    if ($vuln) {
                        push @vulnerabilities, $vuln;
                    }
                };
                if ($@) {
                    my $rule_id = $rule->{id} || "UNKNOWN";
                    warn "Error processing rule $rule_id on file $file: $@\n";
                }
            } 
            # Standard regex pattern rules
            elsif ($rule->{pattern}) {
                my $pattern = $rule->{pattern};
                eval {
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
                };
                if ($@) {
                    my $rule_id = $rule->{id} || "UNKNOWN";
                    warn "Error processing regex rule $rule_id on file $file: $@\n";
                }
            }
        }
    }
    
    return \@vulnerabilities;
}

1;
