my $content = "return n + safe_recursive_call(n - 1)";
if ($content =~ /\bsafe_recursive_call\s*\(/) {
    if ($content !~ /^def\s+/) {
        print "Matches recursive call\n";
    }
}
