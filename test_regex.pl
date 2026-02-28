my @tokens = (
    "def uncontrolled_recursive_call(n):",
    "    return n + uncontrolled_recursive_call(n + 1)"
);

my $current_func = "";
my $func_indent  = 0;
my $has_base_case = 0;

foreach my $content (@tokens) {
    print "EVAL: '$content' | func=$current_func | base=$has_base_case\n";
    if ($content =~ /^(\s*)def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/) {
        $func_indent = length($1);
        $current_func = $2;
        $has_base_case = 0;
        print "  -> Def found. Indent: $func_indent Name: $current_func\n";
        next;
    }
    
    if ($current_func) {
        if ($content =~ /^(\s*)\S/ && length($1) <= $func_indent && $content !~ /^\s*def\s+/) {
            print "  -> Exited block.\n";
            $current_func = "";
            $has_base_case = 0;
            next;
        }
        
        if ($content =~ /^\s*(?:if|elif)\b/) {
            print "  -> Base case found!\n";
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
