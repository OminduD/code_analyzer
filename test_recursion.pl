use strict;
use warnings;
my $file = "dummy_logic/logic.py";
my $lang = "python";
use lib "lib";
use Tokenizer;
my $tokens = Tokenizer::tokenize_file($file, $lang);
foreach my $t (@$tokens) {
    print "Line $t->{line_num}: '$t->{content}'\n";
}
