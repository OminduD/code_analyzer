[
    {
        id       => "ADA001",
        pattern  => qr/(?i)Unchecked_Conversion/,
        message  => "Use of Unchecked_Conversion bypasses type safety",
        severity => "HIGH",
        fix      => "Ensure strict bounds checking before and after conversion",
    },
    {
        id       => "ADA002",
        pattern  => qr/(?i)Unchecked_Deallocation/,
        message  => "Manual memory deallocation can lead to use-after-free",
        severity => "MEDIUM",
        fix      => "Nullify pointers immediately after deallocation",
    }
]
