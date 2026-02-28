[
    {
        id       => 'HASKELL_UNSAFE',
        pattern  => qr/unsafePerformIO/,
        message  => 'unsafePerformIO detected. Bypasses type system safety.',
        severity => 'MEDIUM',
        fix      => 'Avoid using unsafePerformIO. Manage side effects explicitly using the IO monad.'
    }
];
