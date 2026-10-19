package Scanner;

use strict;
use warnings;
use File::Find;
use Carp;

# Scans a directory for matching files based on language extension
sub scan_directory {
    my ($target_dir, $lang) = @_;
    
    my %extensions = (
        'c'          => qr/\.c$/,
        'php'        => qr/\.php$/,
        'python'     => qr/\.py$/,
        'js'         => qr/\.js$/,
        'java'       => qr/\.java$/,
        'rust'       => qr/\.rs$/,
        'lua'        => qr/\.lua$/,
        'go'         => qr/\.go$/,
        'cpp'        => qr/\.(?:cpp|cxx|cc|hpp|h)$/,
        'asm'        => qr/\.(?:asm|s)$/,
        'ada'        => qr/\.(?:adb|ads)$/,
        'cobol'      => qr/\.(?:cbl|cob|cpy)$/,
        'pascal'     => qr/\.(?:pas|inc)$/,
        'ruby'       => qr/\.rb$/,
        'csharp'     => qr/\.cs$/,
        'r'          => qr/\.(?:R|r)$/,
        'swift'      => qr/\.swift$/,
        'kotlin'     => qr/\.kt[s]?$/,
        'typescript' => qr/\.ts$/,
        'scala'      => qr/\.scala$/,
        'perl'       => qr/\.(?:pl|pm|t)$/,
        'bash'       => qr/\.sh$/,
        'haskell'    => qr/\.(?:hs|lhs)$/,
        'env'        => qr/(?:^\.env(?:\.[a-zA-Z0-9_\-]+)?$|\.env$)/,
        'config'     => qr/\.(?:json|ya?ml|toml|ini|conf|cfg|properties|xml)$/i,
        'sql'        => qr/\.sql$/i,
    );
    
    my $ext_regex;
    if (lc($lang) ne 'all') {
        $ext_regex = $extensions{lc($lang)};
        croak "Unsupported language: $lang\n" unless $ext_regex;
    }

    if (!-e $target_dir) {
        croak "Target path does not exist: $target_dir\n";
    }

    my @files;
    
    my $wanted = sub {
        my $file = $_;
        my $dir  = $File::Find::dir;
        
        # Skip ignored directories and version control
        if ($file =~ /^(?:vendor|node_modules|build|dist|\.git|__pycache__|\.idea|\.vscode|\.pytest_cache)$/) {
            $File::Find::prune = 1;
            return;
        }
        
        if (-f $file) {
            # Skip package manager lockfiles to prevent false alarms on package hashes
            return if $file =~ /^(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|Cargo\.lock|Gemfile\.lock)$/;

            if ($ext_regex) {
                # Single language mode
                if ($file =~ /$ext_regex/) {
                    push @files, { path => $File::Find::name, lang => lc($lang) };
                }
            } else {
                # 'all' language mode
                foreach my $l (sort keys %extensions) {
                    my $regex = $extensions{$l};
                    if ($file =~ /$regex/) {
                        push @files, { path => $File::Find::name, lang => $l };
                        last; # Break out of inner loop once matched
                    }
                }
            }
        }
    };
    
    eval {
        find({ wanted => $wanted, no_chdir => 0 }, $target_dir);
    };
    if ($@) {
        carp "Warning: File search interrupted or encountered an error: $@\n";
    }
    
    return \@files;
}

1;
