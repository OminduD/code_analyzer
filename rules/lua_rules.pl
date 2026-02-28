[
    {
        id       => "LUA001",
        pattern  => qr/\bos\.execute\s*\(/,
        message  => "Execution of OS commands using os.execute",
        severity => "HIGH",
        fix      => "Avoid passing unsanitized variables to os.execute",
    },
    {
        id       => "LUA002",
        pattern  => qr/\bloadstring\s*\(/,
        message  => "Execution of arbitrary strings with loadstring",
        severity => "HIGH",
        fix      => "Do not evaluate untrusted input",
    }
]
