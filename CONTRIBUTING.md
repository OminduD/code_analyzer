# Contributing to Perl Static Code Security Analyzer

First off, thank you for considering contributing to the Perl Static Code Security Analyzer! It's people like you that make this tool better for everyone. 

The following is a set of guidelines for contributing to this project. These are mostly guidelines, not rules. Use your best judgment, and feel free to propose changes to this document in a pull request.

## How Can I Contribute?

### Reporting Bugs
This section guides you through submitting a bug report.
- Ensure the bug was not already reported by searching on GitHub under Issues.
- If you're unable to find an open issue addressing the problem, open a new one. Be sure to include a title and clear description, as much relevant information as possible, and a code sample or an executable test case demonstrating the expected behavior that is not occurring.

### Suggesting Enhancements
This section guides you through submitting an enhancement suggestion, including completely new features and minor improvements to existing functionality.
- Open a new issue with a descriptive title and a detailed description of the proposed enhancement.
- Explain why this enhancement would be useful to most users.

### Pull Requests
- Fill in the required template (if any)
- Do not include issue numbers in the PR title
- Include screenshots and animated GIFs in your pull request whenever possible.
- End all files with a newline.
- Place all new rules in the appropriate `rules/<lang>_rules.pl` or universal rules file.
- Document any changes in behavior.

## Extending Rules

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

## Setting up for development

1. Fork the repo and clone it locally.
2. Ensure you have Perl 5.16+ installed.
3. Make changes and test them locally using the `test_project` directory.
   ```bash
   ./bin/analyzer.pl --path ./test_project --lang all
   ```
4. Submit a Pull Request!

Again, thank you for your contribution!
