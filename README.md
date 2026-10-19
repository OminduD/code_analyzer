# Perl Static Code Security Analyzer

A modular, blazing-fast, and lightweight static code analysis CLI tool written in Perl. It scans source code across **over 20+ programming languages** to detect potential security vulnerabilities, bad practices, malware traces, and leaked secrets using a powerful, dynamic regex-based rule engine—without needing to compile or execute the code.

## 🚀 Features

- **Massive Multi-Language Support:** Analyzes Ada, Assembly, Bash, C, C++, C#, COBOL, Go, Haskell, Java, JavaScript, Kotlin, Lua, Pascal, Perl, PHP, Python, R, Ruby, Rust, Scala, Swift, TypeScript, and more.
- **Plagiarism & Code Clone Tracking:** Intelligent token-based structural plagiarism detection across files. Detects **Type-1** (exact duplicates), **Type-2** (renamed variables/identifiers), and **Type-3** (near-miss modified duplicates) with similarity percentage ratings, line spans, and side-by-side comparison.
- **Code Error & Bug Pattern Hunting:** Catches critical runtime bugs and quality issues including division by zero, null/nil pointer dereferences, empty exception swallowing, resource leaks, accidental assignments in `if` conditions, and dead code.
- **Deep Security Vulnerability Rules:** Comprehensive OWASP & CWE categorized rules for SQL Injection, Command Injection, XSS, SSRF, Path Traversal, Insecure Deserialization, and Weak Cryptography.
- **Exposed Secret & API Key Hunter:** Detects over 45+ credential and API exposures across source code and config files:
  - **AI & LLM Providers:** OpenAI (`sk-proj-`, `sk-admin-`, `sk-`), Anthropic Claude (`sk-ant-`), Hugging Face (`hf_`), Google Gemini / MakerSuite (`AIzaSy`), Groq (`gsk_`), Replicate (`r8_`), Cohere, Mistral, and Pinecone vector database keys.
  - **Cloud Infrastructure:** AWS Access Keys (`AKIA`, `ASIA` temporary STS, `AGPA`, `AIDA`, `AROA`), AWS Secret Keys, AWS Session Tokens, GCP Service Account JSON keys, GCP/Firebase API keys, Azure Storage Connection Strings & AccountKeys, Azure AD Client Secrets, DigitalOcean tokens (`dop_v1_`), Alibaba Cloud AccessKeys, and Heroku API keys.
  - **Developer Platforms & Package Registries:** GitHub Classic & Fine-Grained tokens (`ghp_`, `github_pat_`, `gho_`), GitLab tokens (`glpat-`, `glptt-`), NPM publish tokens (`npm_`), PyPI upload tokens (`pypi-`), Docker Hub PATs, and Postman API keys.
  - **SaaS, Payments & Webhooks:** Stripe live & restricted keys (`sk_live_`, `rk_live_`, `whsec_`), Square tokens, PayPal client secrets, Slack incoming webhooks & bot tokens (`xoxb-`, `xoxp-`), Discord webhooks & bot tokens, Telegram bot tokens, Twilio Account SIDs & auth tokens, SendGrid API keys, Mailgun keys, and Datadog keys.
  - **Cryptographic & Transport Secrets:** Committed Private Keys (RSA, DSA, EC, OpenSSH, PGP, PuTTY), Database connection URIs with embedded plaintext credentials (PostgreSQL, MySQL, MongoDB, Redis, RabbitMQ), JWT tokens, and HTTP Basic Auth in URLs.
  - **Shannon Entropy Engine:** Heuristic detector that calculates Shannon information entropy (bits/character) to flag proprietary, in-house, or custom high-entropy secret API tokens that lack known vendor prefixes.
- **Config & Environment File Auditing:** Scans `.env`, `.env.local`, `.env.production`, `.json`, `.yaml`, `.yml`, `.toml`, `.ini`, `.conf`, and `.sql` files automatically in `--lang all` or via `--lang env` and `--lang config`.
- **Universal Malware Scanning:** Global rule engine automatically hunts for reverse shells, fork bombs, keyloggers, backdoor listeners, trojans, hidden processes, and malware persistence signatures across *all* analyzed files.
- **Intelligent Tokenizer:** Pre-processes code to strip block and inline comments prior to scanning, significantly reducing false positives.
- **Rich Reporting Ecosystem:**
  - **Terminal Output:** Color-coded CLI output with categorized breakdowns and clone highlights.
  - **JSON Dumps:** Export detailed scan results with CWE tags and full plagiarism metadata for CI/CD pipeline integrations.
  - **Interactive HTML Dashboard:** Standalone Neo-Brutalist Bento dashboard featuring interactive Radar Defense health charts, Donut threat breakdowns, Bar charts, Category filtering, and a dedicated Plagiarism Diff Inspector.
  - **Built-in Web Server:** Serve HTML reports instantly locally via the `--serve` flag.
- **Risk & Quality Scoring:** Calculates both a project-wide Security Risk Score (`LOW`, `MODERATE`, `CRITICAL`) and a Code Quality Health Index with letter grades (`A+` to `F`).
- **Dynamic Rules System:** Rules are decoupled from the core logic, categorized by language, and easily extensible following the Open-Closed Principle.
- **Filter & Search:** Target specific files and filter output by severity thresholds or issue categories.

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

3. **Run the analyzer** by passing the required flags (`--path` and `--lang`):

   ```bash
   ./bin/analyzer.pl --path ./test_project --lang all
   ```

   *Note: If you run into permission issues, you can also execute it directly via the Perl interpreter: `perl bin/analyzer.pl ...`*

## ⚙️ Command-Line Flags and Options

Below is a complete list of all available flags, what they do, and how to use them:

| Flag | Status | Description | Example |
| :--- | :--- | :--- | :--- |
| `--path <dir>` | **Required** | Target directory containing the source code to scan. | `--path /var/www/html` |
| `--lang <name>` | **Required** | Language or target to scan (`all`, `c`, `cpp`, `php`, `python`, `js`, `java`, `rust`, `go`, `lua`, `asm`, `ada`, `cobol`, `pascal`, `ruby`, `csharp`, `r`, `swift`, `kotlin`, `typescript`, `scala`, `perl`, `bash`, `haskell`, `env`, `config`, `sql`). | `--lang python` |
| `--json <file>` | *Optional* | Export scan results in structured JSON format including plagiarism and CWE metadata. | `--json report.json` |
| `--html <file>` | *Optional* | Custom filename for the generated HTML dashboard (defaults to `security_report.html`). | `--html audit-2026.html` |
| `--severity <level>` | *Optional* | Filter findings by severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). | `--severity HIGH` |
| `--type <category>` | *Optional* | Filter findings by category (`all`, `vulnerability`, `error`, `malware`, `secret`). | `--type error` |
| `--no-plagiarism` | *Optional* | Disables plagiarism and code clone detection. | `--no-plagiarism` |
| `--min-similarity <pct>` | *Optional* | Minimum similarity threshold percentage to flag code clones (default: `50`). | `--min-similarity 75` |
| `--serve` | *Optional* | Spins up a local web server (port `8000`) to view the interactive dashboard. | `--serve` |

## 📖 Usage Examples

### Basic Scan (Terminal Output & Default HTML)

Scan a directory for a specific language. This prints results to the terminal and generates `security_report.html`.

```bash
./bin/analyzer.pl --path /path/to/project --lang python
```

### Universal Scan (All Languages)

Scan a directory across all supported languages, universal malware rules, and plagiarism analysis.

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
│   ├── PlagiarismDetector.pm # Multi-language code clone and plagiarism detector
│   ├── Reporter.pm           # Output generator (ANSI Terminal, JSON, HTML Bento Dashboard)
│   └── Scorer.pm             # Risk calculator, quality index, and originality scorer
│
├── rules/                    # 20+ Modular language & universal rule definitions
│   ├── secrets_rules.pl      # Universal rules for API keys, tokens, and credentials
│   ├── malware_rules.pl      # Universal rules for malware/virus signatures
│   ├── js_rules.pl           # JavaScript vulnerabilities and code errors
│   ├── java_rules.pl         # Java vulnerabilities and code errors
│   ├── c_rules.pl            # C specific vulnerabilities and code errors
│   ├── php_rules.pl          # PHP specific vulnerabilities and code errors
│   └── ...                   # (Rules for Python, Go, TypeScript, Ruby, Bash, Rust, etc.)
│
└── test_project/             # Example sandbox codebase across multiple languages for testing
```

## ⚖️ Scoring System

The engine evaluates code and tallies points based on findings:

- **CRITICAL:** 15 Points
- **HIGH:** 10 Points
- **MEDIUM:** 5 Points
- **LOW:** 1 Point

Based on the cumulative sum of all files scanned, a risk category is assigned:

- **`LOW`** (0 - 10 points): Acceptable baseline risk.
- **`MODERATE`** (11 - 30 points): Needs attention and refactoring.
- **`CRITICAL`** (> 30 points): Hazardous codebase requiring immediate remediation.

Additionally, a **Code Quality Health Index** (0% to 100%) and letter grade (`A+` to `F`) is calculated based on code error density and severity.

## 🧩 How to Extend Rules

The core engine is entirely decoupled from the ruleset. To add a new rule for an existing language, simply append a block into the respective `rules/<lang>_rules.pl` array.

For example, to add a new PHP rule inside `rules/php_rules.pl`:

```perl
    {
        id       => "PHP005",
        type     => "error",
        cwe      => "CWE-480",
        pattern  => qr/\bvar_dump\s*\(/,
        message  => "Production usage of var_dump() can leak sensitive information",
        severity => "LOW",
        fix      => "Remove var_dump() before production deployment",
    }
```

If you wish to add **Global Secret or Malware rules**, update `rules/secrets_rules.pl` or `rules/malware_rules.pl`.

**Required Rule Fields:**

- `id`: A unique identifier string for the rule.
- `pattern`: A compiled regular expression (`qr//`) to match the vulnerability or error.
- `message`: A descriptive summary of what the rule detects.
- `severity`: Must be `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.
- `fix`: A suggested remediation step.
- `type` *(Optional)*: `vulnerability`, `error`, `malware`, or `secret`.
- `cwe` *(Optional)*: Common Weakness Enumeration ID (e.g. `CWE-89`).

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

Feel free to check out the [issues page](https://github.com/OminduD/code_analyzer/issues) if you want to contribute. For detailed instructions on how to set up the development environment, extend the rules, and submit Pull Requests, please read the [Contributing Guidelines](CONTRIBUTING.md).

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
