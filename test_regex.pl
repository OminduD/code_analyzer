my $content = "return n + safe_recursive_call(n - 1)";
my $has_base_case = 0;
if ($content =~ /^(?:if|elif)\s+/) {
    $has_base_case = 1;
}

if ($content =~ /\bsafe_recursive_call\s*\(/) {
    if (!$has_base_case) {
        print "CRITICAL: No base case found before this recursion!\n";
    } else {
        print "SAFE: Base case exists.\n";
    }
}
