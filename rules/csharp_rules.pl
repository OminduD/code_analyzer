[
    {
        id       => 'CSHARP_UNSAFE',
        pattern  => qr/unsafe\s*\{/,
        message  => 'Unsafe code block detected. Ensure memory safety.',
        severity => 'MEDIUM',
        fix      => 'Review the need for unsafe code block.'
    }
];
