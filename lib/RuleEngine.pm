package RuleEngine;

use strict;
use warnings;
use File::Spec;
use Carp;

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
        carp "Error compiling rules from $rule_file: $@\n";
        return [];
    } elsif (!defined $rules) {
        carp "Error reading rules from $rule_file: $!\n";
        return [];
    }
    
    if (ref($rules) ne 'ARRAY') {
        carp "Rules must be an array reference in $rule_file\n";
        return [];
    }
    
    return $rules;
}

# Helper to infer finding category (vulnerability, error, malware, secret)
sub _infer_type {
    my ($rule) = @_;
    return lc($rule->{type}) if $rule->{type};
    
    my $id = $rule->{id} || '';
    my $msg = lc($rule->{message} || '');

    if ($id =~ /^(?:MAL|VIRUS|WORM|TROJAN|ROOTKIT)/i || $msg =~ /(?:trojan|malware|reverse shell|backdoor|miner|fork bomb|keylogger|persistence)/i) {
        return 'malware';
    } elsif ($id =~ /^SEC/i || $msg =~ /(?:secret|password|credential|private key|token|api_key)/i) {
        return 'secret';
    } elsif ($id =~ /^(?:ERR|BUG|QLTY)/i || $msg =~ /(?:null pointer|nil dereference|resource leak|dead code|unreachable|divide by zero|division by zero|loose equality|unhandled|unclosed|syntax error)/i) {
        return 'error';
    }
    return 'vulnerability';
}

# Runs the rules against tokenized file content
sub analyze {
    my ($file, $tokens, $rules) = @_;
    
    my @vulnerabilities;
    my %seen_findings; # Avoid duplicate alerts on exact same line + rule_id
    
    # 1. Token-level analysis
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
                        $vuln->{type} ||= _infer_type($rule);
                        $vuln->{cwe}  ||= $rule->{cwe} || '';
                        
                        my $key = "$file:$vuln->{line}:$vuln->{rule_id}";
                        unless ($seen_findings{$key}++) {
                            push @vulnerabilities, $vuln;
                        }
                    }
                };
                if ($@) {
                    my $rule_id = $rule->{id} || "UNKNOWN";
                    carp "Error processing rule $rule_id on file $file: $@\n";
                }
            } 
            # Standard regex pattern rules
            elsif ($rule->{pattern}) {
                my $pattern = $rule->{pattern};
                eval {
                    if ($content =~ /$pattern/) {
                        my $type = _infer_type($rule);
                        my $key = "$file:$line_num:$rule->{id}";
                        unless ($seen_findings{$key}++) {
                            push @vulnerabilities, {
                                file     => $file,
                                line     => $line_num,
                                rule_id  => $rule->{id},
                                message  => $rule->{message},
                                severity => $rule->{severity},
                                fix      => $rule->{fix},
                                snippet  => $content,
                                type     => $type,
                                cwe      => $rule->{cwe} || '',
                            };
                        }
                    }
                };
                if ($@) {
                    my $rule_id = $rule->{id} || "UNKNOWN";
                    carp "Error processing regex rule $rule_id on file $file: $@\n";
                }
            }
        }
    }
    
    # 2. File-level rules (whole-file context, e.g., resource leaks, unclosed handles)
    foreach my $rule (@$rules) {
        if ($rule->{file_func}) {
            eval {
                my $findings = $rule->{file_func}->($file, $tokens, \@vulnerabilities);
                if ($findings) {
                    my @arr = ref($findings) eq 'ARRAY' ? @$findings : ($findings);
                    foreach my $vuln (@arr) {
                        next unless ref($vuln) eq 'HASH';
                        $vuln->{type} ||= _infer_type($rule);
                        $vuln->{cwe}  ||= $rule->{cwe} || '';
                        
                        my $key = "$file:$vuln->{line}:$vuln->{rule_id}";
                        unless ($seen_findings{$key}++) {
                            push @vulnerabilities, $vuln;
                        }
                    }
                }
            };
            if ($@) {
                my $rule_id = $rule->{id} || "UNKNOWN";
                carp "Error processing file-level rule $rule_id on file $file: $@\n";
            }
        }
    }
    
    return \@vulnerabilities;
}

1;
