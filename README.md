# Perl Static Code Security Analyzer

A modular, blazing-fast, and lightweight static code analysis CLI tool written in Perl. It scans source code across **over 20+ programming languages** to detect potential security vulnerabilities, bad practices, malware traces, and leaked secrets using a powerful, dynamic regex-based rule engine—without needing to compile or execute the code.

## 🚀 Features

- **Massive Multi-Language Support:** Analyzes Ada, Assembly, Bash, C, C++, C#, COBOL, Go, Haskell, Kotlin, Lua, Pascal, Perl, PHP, Python, R, Ruby, Rust, Scala, Swift, TypeScript, and more.
- **Universal Secrets & Malware Scanning:** Global rule engine automatically hunts for leaked API keys, tokens, hardcoded passwords, credentials, and known malware signatures across *all* analyzed files.
- **Intelligent Tokenizer:** Pre-processes code to strip block and inline comments prior to scanning, significantly reducing false positives.
- **Rich Reporting Ecosystem:**
  - **Terminal Output:** Beautiful, color-coded CLI output.
  - **JSON Dumps:** Export detailed scan results for CI/CD pipeline integrations.
  - **Interactive HTML Dashboard:** Generates a stunning standalone HTML report with risk breakdown charts and top vulnerability tracking.
  - **Built-in Web Server:** Serve HTML reports instantly locally via the `--serve` flag.
- **Risk & Severity Scoring:** Calculates a weighted Risk Score (based on vulnerabilities' severity: `HIGH`, `MEDIUM`, `LOW`) and assigns a project-wide rating: `LOW`, `MODERATE`, or `CRITICAL`.
- **Dynamic Rules System:** Rules are decoupled from the core logic, categorized by language, and easily extensible following the Open-Closed Principle.
- **Filter & Search:** Target specific files and filter output by severity thresholds.

## 📋 Requirements

To run the Perl Static Code Security Analyzer, ensure your system meets the following prerequisites:

- **Perl 5.16+** (Unix-like systems usually come with Perl pre-installed. Windows users can use Strawberry Perl).
- **Standard Core Perl Modules** (These are typically included with your Perl installation):
  - `strict`
  - `warnings`
  - `Getopt::Long`
  - `File::Spec`
  - `FindBin`
  - `Carp`
  - `Term::ANSIColor`
  - `JSON::PP` (Used for JSON reporting)
  - `File::Find` (Used for traversing directories)
- **Python 3 [Optional]** - Only required if you intend to use the `--serve` flag to instantly spawn a local web server to view the HTML dashboard.

## 🛠️ How to Run the Program Correctly

1. **Clone the repository** (or download the source code) to your local machine:
   ```bash
   git clone https://github.com/OminduD/code_analyzer.git
   cd code_analyzer
   ```

2. **Make the analyzer executable** (Linux/macOS):
   ```bash
   chmod +x bin/analyzer.pl
   ```

3. **Run the analyzer** by passing the required flags (`--path` and `--lang`).
   ```bash
   ./bin/analyzer.pl --path ./test_project --lang all
   ```
   *Note: If you run into permission issues, you can also execute it directly via the Perl interpreter: `perl bin/analyzer.pl ...`*

## ⚙️ Command-Line Flags and Options

Below is a complete list of all available flags, what they do, and how to use them:

| Flag | Status | Description | Example |
| :--- | :--- | :--- | :--- |
| `--path <dir>` | **Required** | Specifies the target directory containing the source code you want to scan. | `--path /var/www/html` |
| `--lang <name>` | **Required** | The programming language to scan for. You can specify a single language or use `all` to scan every supported language in the directory. <br><br>**Supported values:** `all`, `c`, `cpp`, `php`, `python`, `js`, `java`, `rust`, `go`, `lua`, `asm`, `ada`, `cobol`, `pascal`, `ruby`, `csharp`, `r`, `swift`, `kotlin`, `typescript`, `scala`, `perl`, `bash`, `haskell`. | `--lang python` |
| `--json <file>` | *Optional* | Instructs the tool to export the scan results in structured JSON format to the specified file path. Useful for CI/CD integrations. | `--json report.json` |
| `--html <file>` | *Optional* | Customizes the filename for the generated HTML report. (If not provided, the tool defaults to generating `security_report.html` in the current directory). | `--html audit-2023.html` |
| `--severity <level>` | *Optional* | Filters the reported vulnerabilities to only show issues matching the specified severity level. <br><br>**Valid options:** `LOW`, `MEDIUM`, `HIGH`. | `--severity HIGH` |
| `--serve` | *Optional* | Automatically spins up a local Python 3 web server (on port `8000`) to host and display the generated HTML dashboard immediately after the scan. | `--serve` |

## 📖 Usage Examples

### Basic Scan (Terminal Output & Default HTML)
Scan a directory for a specific language. This will print results to the terminal and generate `security_report.html`.
```bash
./bin/analyzer.pl --path /path/to/project --lang python
```

### Universal Scan (All Languages)
Scan a directory across all supported languages and universal rules (malware/secrets).
```bash
./bin/analyzer.pl --path ./test_project --lang all
```

### Advanced Scan (JSON, HTML & Severity Filtering)
Generate multiple report formats, filtering only for `HIGH` severity issues.
```bash
./bin/analyzer.pl --path ../my-app --lang typescript --severity HIGH --json out_report.json --html detailed_report.html
```

### 🌐 Instant Dashboard Serving
Generate an HTML report and instantly spin up a local web dashboard to view it in your browser.
```bash
./bin/analyzer.pl --path ./test_project --lang all --serve
```
*(Automatically starts a web server on `http://localhost:8000` to view the comprehensive UI!)*

## 📂 Project Structure

```text
code_analyzer/
│
├── bin/
│   └── analyzer.pl           # Main executable CLI application
│
├── lib/
│   ├── Scanner.pm            # File discovery engine and extension mappings
│   ├── Tokenizer.pm          # Code parser and comment stripping utility
│   ├── RuleEngine.pm         # Dynamic pattern matcher & language rule loader
│   ├── Reporter.pm           # Output generator (ANSI Terminal, JSON, HTML)
│   └── Scorer.pm             # Risk calculator and vulnerability weighting
│
├── rules/                    # 20+ Modular language & universal rule definitions
│   ├── secrets_rules.pl      # Universal rules for API keys and tokens
│   ├── malware_rules.pl      # Universal rules for malware/virus signatures
│   ├── c_rules.pl            # C specific anti-patterns
│   ├── php_rules.pl          # PHP specific warnings
│   └── ...                   # (Rules for Go, TypeScript, Ruby, Bash, etc.)
│
└── test_project/             # Example sandbox codebase across multiple languages for testing
```

## ⚖️ Scoring System
The engine evaluates code and tallies points based on findings:
* **HIGH:** 10 Points
* **MEDIUM:** 5 Points
* **LOW:** 1 Point

Based on the cumulative sum of all files scanned, a risk category is assigned:
- **`LOW`** (0 - 10 points): Acceptable baseline risk.
- **`MODERATE`** (11 - 30 points): Needs attention and refactoring.
- **`CRITICAL`** (> 30 points): Hazardous codebase requiring immediate remediation.

## 🧩 How to Extend Rules

The core engine is entirely decoupled from the ruleset. To add a new rule for an existing language, simply append a block into the respective `rules/<lang>_rules.pl` array.

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
If you wish to add **Global Secret or Malware rules**, update `rules/secrets_rules.pl` or `rules/malware_rules.pl`.

**Required Rule Fields:**
- `id`: A unique identifier string for the rule.
- `pattern`: A compiled regular expression (`qr//`) to match the vulnerability.
- `message`: A descriptive summary of what the rule detects.
- `severity`: Must be `HIGH`, `MEDIUM`, or `LOW`.
- `fix`: A suggested remediation step.

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

Feel free to check out the [issues page](https://github.com/OminduD/code_analyzer/issues) if you want to contribute. For detailed instructions on how to set up the development environment, extend the rules, and submit Pull Requests, please read the [Contributing Guidelines](CONTRIBUTING.md).

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
