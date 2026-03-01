[
    {
        id       => 'BASH001',
        pattern  => qr/eval\s+/,
        message  => 'eval command detected. Can execute arbitrary code.',
        severity => 'HIGH',
        fix      => 'Avoid eval; use safer shell constructs.'
    },
    {
        id       => "GEN999",
        pattern  => qr/(?i)(Software(?:\\|\/)Microsoft(?:\\|\/)Windows(?:\\|\/)CurrentVersion(?:\\|\/)Run|\.config(?:\\|\/)autostart)/,
        message  => "Potential malware persistence mechanism detected (Windows Run key or Linux autostart)",
        severity => "HIGH",
        fix      => "Remove auto-start functionality unless explicitly required by the application",
    },
    {
        id       => "BASH002",
        pattern  => qr/:\s*\(\s*\)\s*\{\s*:\s*\|\s*:&\s*\}/,
        message  => "Fork bomb detected: ':(){ :|:& };:' pattern. This spawns processes exponentially and will crash/hang the system.",
        severity => "CRITICAL",
        fix      => "Remove the fork bomb. Use ulimit to restrict process creation in production environments.",
    },
    {
        id       => "BASH003",
        pattern  => qr/(?:for|while|until)\b.*?(?:\n.*?){0,5}\bmkdir\b/s,
        message  => "Potential directory bomb: mkdir called inside a loop. This can create thousands of directories and exhaust filesystem resources.",
        severity => "HIGH",
        fix      => "Bound the number of directories created in loops. Validate the target path before creation.",
    },
    {
        id       => "BASH004",
        pattern  => qr/(?:curl|wget)\s+.*?\|\s*(?:ba)?sh\b|wget\s+.*?-O\s*-\s*\|\s*(?:ba)?sh\b/,
        message  => "Remote code execution via pipe: curl/wget output piped directly to sh/bash. This downloads and immediately executes arbitrary remote code without any verification.",
        severity => "CRITICAL",
        fix      => "Download scripts to a file first, inspect them, then execute explicitly. Never pipe remote content directly to a shell interpreter.",
    },
    {
        id       => "BASH005",
        pattern  => qr/(?:crontab\s+-[li]|echo\s+.*?>>?\s*\/etc\/cron|tee\s+\/etc\/cron|\/etc\/cron\.d\/)/,
        message  => "Cron-based persistence mechanism: writing to /etc/cron* or modifying crontab detected. Malware commonly uses cron to survive system reboots.",
        severity => "HIGH",
        fix      => "Review all cron modifications. Persistence mechanisms must be explicit, documented, and require user consent.",
    },
    {
        id       => "BASH006",
        pattern  => qr/bash\s+-i\s+>\s*&\s*\/dev\/tcp\/|nc\s+.*?-e\s+(?:\/bin\/(?:ba)?sh|cmd\.exe)|socat\s+.*?EXEC:.*?(?:\/bin\/sh|bash)/,
        message  => "Reverse shell detected: bash /dev/tcp redirection, netcat -e /bin/sh, or socat shell execution pattern. This opens an interactive shell to a remote attacker.",
        severity => "CRITICAL",
        fix      => "Remove all reverse shell code. Use SSH or authorised remote management tools instead.",
    },
    {
        id       => "BASH007",
        pattern  => qr/(?:cat\s+>|echo\s+.*?>+|tee\s+)\s*.*?\.(?:sh|bash|bat|cmd|ps1|vbs|py|pl|rb)\b/,
        message  => "Script dropper: writing content to an executable script file (.sh/.bat/.ps1/.py/.vbs etc.) from within this script. This is a common malware staging technique.",
        severity => "CRITICAL",
        fix      => "Do not dynamically generate and write executable scripts. Use configuration or data files instead.",
    },
]
