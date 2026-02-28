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
    );
    
    my $ext_regex = $extensions{lc($lang)};
    die "Unsupported language: $lang\n" unless $ext_regex;

    my @files;
    
    my $wanted = sub {
        my $file = $_;
        my $dir  = $File::Find::dir;
        
        # Skip ignored directories
        if ($file eq 'vendor' || $file eq 'node_modules' || $file eq 'build') {
            $File::Find::prune = 1;
            return;
        }
        
        # Match files by extension
        if (-f $file && $file =~ /$ext_regex/) {
            push @files, $File::Find::name;
        }
    };
    
    find({ wanted => $wanted, no_chdir => 0 }, $target_dir);
    
    return \@files;
}

1;
