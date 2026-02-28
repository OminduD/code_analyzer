use strict;
use warnings;
use Data::Dumper;
my $file = "rules/secrets_rules.pl";
my $rules = do $file;
print Dumper($rules);
