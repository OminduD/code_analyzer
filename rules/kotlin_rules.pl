[
    {
        id       => 'KOTLIN_EVAL',
        pattern  => qr/ScriptEngineManager/,
        message  => 'Script engine usage detected. Potential for injection.',
        severity => 'HIGH',
        fix      => 'Avoid evaluating arbitrary scripts.'
    }
];
