# Perl Static Code Security Analyzer

A modular, blazing-fast, and lightweight static code analysis CLI tool written in Perl. It scans source code across **over 20+ programming languages** to detect potential security vulnerabilities, bad practices, and leaked secrets using a powerful, dynamic regex-based rule engine—without needing to compile or execute the code.

## 🚀 Features

- **Massive Multi-Language Support:** Analyzes Ada, Assembly, Bash, C, C++, C#, COBOL, Go, Haskell, Kotlin, Lua, Pascal, Perl, PHP, Python, R, Ruby, Rust, Scala, Swift, and TypeScript.
- **Universal Secrets Scanning:** Global rule engine automatically hunts for leaked API keys, tokens, hardcoded passwords, and credentials across *all* analyzed files.
- **Intelligent Tokenizer:** Pre-processes code to strip block and inline comments prior to scanning, significantly reducing false positives.
- **Rich Reporting Ecosystem:**
  - **Terminal Output:** Beautiful, color-coded CLI output.
  - **JSON Dumps:** Export detailed scan results for CI/CD pipeline integrations.
  - **Interactive HTML Dashboard:** Generates a stunning standalone HTML report with risk breakdown charts (Chart.js) and top vulnerability tracking.
  - **Built-in Web Server:** Serve HTML reports instantly locally via the `--serve` flag.
- **Risk & Severity Scoring:** Calculates a weighted Risk Score (based on vulnerabilities' severity: `HIGH`, `MEDIUM`, `LOW`) and assigns a project-wide rating: `LOW`, `MODERATE`, or `CRITICAL`.
- **Dynamic Rules System:** Rules are thoroughly decoupled from the core logic, categorized by language, and easily extensible following the Open-Closed Principle.
- **Filter & Search:** Target specific files and filter output by severity thresholds.

## 📂 Project Structure

```text
code_analyzer/
│
├── bin/
│   └── analyzer.pl           # Main executable application
│
├── lib/
│   ├── Scanner.pm            # File discovery engine and extension mappings
│   ├── Tokenizer.pm          # Code parser and comment stripping utility
│   ├── RuleEngine.pm         # Dynamic pattern matcher & language rule loader
│   ├── Reporter.pm           # Output generator (ANSI Terminal, JSON, HTML)
│   └── Scorer.pm             # Risk calculator and vulnerability weighting
│
├── rules/                    # 20+ Modular language rule definitions
│   ├── secrets_rules.pl      # Universal rules for API keys and tokens
│   ├── c_rules.pl            # C specific anti-patterns
│   ├── python_rules.pl       # Python specific warnings
│   ├── rust_rules.pl         # Rust specific warnings
│   └── ...                   # (Rules for Go, TypeScript, Ruby, Bash, etc.)
│
└── test_project/             # Example sandbox codebase across multiple languages for testing
```

## 🛠️ Usage

### Basic Scan (Terminal Output)
Scan a directory for a given language.
```bash
./bin/analyzer.pl --path /path/to/project --lang python
```
*Tip: Use `--lang all` to scan the directory across all supported languages.*

### Advanced Scan (JSON, HTML & Severity Filtering)
Generate multiple report formats on a specific severity factor.
```bash
./bin/analyzer.pl --path /path/to/project --lang typescript --severity HIGH --json report.json --html my_report.html
```

### 🌐 Instant Dashboard Serving
Generate an HTML report and instantly spin up a local web dashboard to view it.
```bash
./bin/analyzer.pl --path /path/to/project --lang all --serve
```
*(Automatically starts a web server on `http://localhost:8000` to view the comprehensive UI!)*

## ⚖️ Scoring System
The engine evaluates code and tallies points based on findings:
* **HIGH:** 10 Points
* **MEDIUM:** 5 Points
* **LOW:** 1 Point

Based on the cumulative sum, a risk category is assigned:
- **`LOW`** (0 - 10): Acceptable baseline risk.
- **`MODERATE`** (11 - 30): Needs attention and refactoring.
- **`CRITICAL`** (> 30): Hazardous codebase requiring immediate remediation.

## 🧩 How to Extend Rules

The core engine is entirely decoupled from the ruleset. To add a new rule for an existing language, simply append a block into the respective `rules/<lang>_rules.pl` map.

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
If you wish to add **Global Secret rules**, update `rules/secrets_rules.pl`.

* You must provide an `id`, `pattern` (as a compiled `qr//` regex), `message`, `severity` (HIGH/MEDIUM/LOW), and a suggested `fix` description.

## ⚙️ Requirements
- **Perl 5.16+**
- Standard core modules: `strict`, `warnings`, `File::Find`, `File::Spec`, `FindBin`, `Getopt::Long`, `JSON::PP`, `Term::ANSIColor`.
- Python 3 *([Optional] - Only used if triggering the `--serve` local webserver flag)*.
