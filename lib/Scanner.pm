package Scanner;

use strict;
use warnings;
use File::Find;

# Scans a directory for matching files based on language extension
sub scan_directory {
    my ($target_dir, $lang) = @_;
    
    my %extensions = (
        'c'      => qr/\.c$/,
        'php'    => qr/\.php$/,
        'python' => qr/\.py$/,
        'js'     => qr/\.js$/,
        'java'   => qr/\.java$/,
        'rust'   => qr/\.rs$/,
        'lua'    => qr/\.lua$/,
        'go'     => qr/\.go$/,
        'cpp'    => qr/\.(?:cpp|cxx|cc|hpp|h)$/,
        'asm'    => qr/\.(?:asm|s)$/,
        'ada'    => qr/\.(?:adb|ads)$/,
        'cobol'  => qr/\.(?:cbl|cob|cpy)$/,
        'pascal' => qr/\.(?:pas|inc)$/,
        'ruby'   => qr/\.rb$/,
        'csharp' => qr/\.cs$/,
        'r'      => qr/\.(?:R|r)$/,
        'swift'  => qr/\.swift$/,
        'kotlin' => qr/\.kt[s]?$/,
        'typescript' => qr/\.ts$/,
        'scala'  => qr/\.scala$/,
        'perl'   => qr/\.(?:pl|pm|t)$/,
        'bash'   => qr/\.sh$/,
        'haskell' => qr/\.(?:hs|lhs)$/,
    );
    
    my $ext_regex;
    if (lc($lang) ne 'all') {
        $ext_regex = $extensions{lc($lang)};
        die "Unsupported language: $lang\n" unless $ext_regex;
    }

    my @files;
    
    my $wanted = sub {
        my $file = $_;
        my $dir  = $File::Find::dir;
        
        # Skip ignored directories
        if ($file eq 'vendor' || $file eq 'node_modules' || $file eq 'build') {
            $File::Find::prune = 1;
            return;
        }
        
        if (-f $file) {
            if ($ext_regex) {
                # Single language mode
                if ($file =~ /$ext_regex/) {
                    push @files, { path => $File::Find::name, lang => lc($lang) };
                }
            } else {
                # 'all' language mode
                foreach my $l (keys %extensions) {
                    my $regex = $extensions{$l};
                    if ($file =~ /$regex/) {
                        push @files, { path => $File::Find::name, lang => $l };
                        last; # Break out of inner loop once matched
                    }
                }
            }
        }
    };
    
    find({ wanted => $wanted, no_chdir => 0 }, $target_dir);
    
    return \@files;
}

1;
