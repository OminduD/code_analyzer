# Perl Static Code Security Analyzer

A modular and lightweight static code analysis CLI tool written in Perl. It scans C, PHP, and Python source code to detect potential security vulnerabilities using extensive regex-based rules without executing the code.

## Features
- **Multi-language Support:** C, PHP, and Python.
- **Comment Stripping:** Uses an intelligent tokenizer to strip block and inline comments before scanning to avoid false positives.
- **Reporting Formats:** Generates reports in rich Terminal view, JSON output, or HTML summary tables.
- **Dynamic Rules Engine:** Rules are stored in cleanly defined arrays and loaded dynamically, adhering to the Open-Closed Principle.
- **Severity & Scoring System:** Calculates a final Risk Score and determines the system category (LOW, MODERATE, CRITICAL).

## Project Structure
```text
mini-analyzer/
│
├── bin/
│   └── analyzer.pl       (Main CLI application)
│
├── lib/
│   ├── Scanner.pm        (File discovery using File::Find)
│   ├── Tokenizer.pm      (Comment parsing and striping engine)
│   ├── RuleEngine.pm     (Pattern matcher & rules loader)
│   ├── Reporter.pm       (Terminal, JSON, HTML formatting)
│   └── Scorer.pm         (Risk analyzer mapping scores)
│
├── rules/
│   ├── c_rules.pl        (C specific vulnerabilities list)
│   ├── php_rules.pl      (PHP patterns)
│   └── python_rules.pl   (Python patterns)
│
├── test_project/         (Example dummy codebase for testing)
│
└── reports/              (Generated outputs like JSON and HTML dumps)
```

## How to Run

1. **Terminal Output**
   ```bash
   ./bin/analyzer.pl --path /path/to/project --lang c
   ```

2. **Terminal Output with Output Dumps**
   ```bash
   ./bin/analyzer.pl --path /path/to/project --lang php --json reports/php_dump.json --html reports/php_summary.html
   ```

3. **Filtering by Severity**
   ```bash
   ./bin/analyzer.pl --path /path/to/project --lang python --severity HIGH
   ```

## How to Extend Rules

The core engine is decoupled from the ruleset. To add a new rule for a language, simply append a block into the respective `rules/<lang>_rules.pl` array.

For example, to add a new PHP rule inside `rules/php_rules.pl`:
```perl
    {
        id       => "PHP005",
        pattern  => qr/\bvar_dump\s*\(/,
        message  => "Production usage of var_dump() can leak sensitive information",
        severity => "LOW",
        fix      => "Remove var_dump() before production deployment",
    }
```
*   You must provide an `id`, `pattern` (as a `qr//` regex), `message`, `severity` (HIGH/MEDIUM/LOW), and a suggested `fix` description.

## Requirements
- Perl 5.16+
- Standard core modules: `strict`, `warnings`, `File::Find`, `File::Spec`, `FindBin`, `Getopt::Long`, `JSON::PP`, `Term::ANSIColor`.
