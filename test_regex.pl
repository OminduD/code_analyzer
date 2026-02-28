my @tokens = (
    "def safe_recursive_call(n):",
    "if n <= 0:",
    "return 0",
    "return n + safe_recursive_call(n - 1)"
);

my $current_func = "";
my $has_base_case = 0;

foreach my $content (@tokens) {
    print "EVAL: $content | func=$current_func | base=$has_base_case\n";
    if ($content =~ /^def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/) {
        $current_func = $1;
        $has_base_case = 0;
        next;
    }
    
    if ($current_func) {
        if ($content =~ /^(def|class)\b/ && $content !~ /^def\s+$current_func\s*\(/) {
            $current_func = "";
            $has_base_case = 0;
            next;
        }
        
        if ($content =~ /^(?:if|elif|return)\b/) {
            $has_base_case = 1;
        }
        
        if ($content =~ /\b$current_func\s*\(/) {
            if (!$has_base_case) {
                print "  -> CRITICAL ALERT!!!\n";
            } else {
                print "  -> SAFE\n";
            }
        }
    }
}
