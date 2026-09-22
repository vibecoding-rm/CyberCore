# Contributing to CyberCore

Thank you for contributing to CyberCore! We welcome contributions that align with our core mission: providing a safe, defensive, evidence-backed security analysis platform.

## Development Workflow

1. **Fork and Clone**:
   ```bash
   git clone https://github.com/your-username/CyberCore.git
   cd CyberCore
   ```

2. **Environment Setup**:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Or on Windows: .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   cp .env.example .env
   ```

3. **Start Local Services (Docker)**:
   ```bash
   docker compose up -d postgres ollama
   ```

4. **Apply Database Migrations & Seed Baseline Feeds**:
   ```bash
   python scripts/migrate_db.py
   python scripts/ingest_vulnerabilities.py --baseline
   ```

5. **Run the Test Suite**:
   Make sure all tests pass before submitting any changes:
   ```bash
   pytest
   ```
   To run PostgreSQL integration tests locally:
   ```bash
   export CYBERCORE_TEST_DATABASE_URL="postgresql://cybercore:change_me@127.0.0.1:5432/cybercore"
   pytest
   ```

## Contribution Rules

- **Zero Tolerance for Arbitrary Execution**: Never introduce unconstrained shell execution for LLMs. All tools must inherit from `ToolAdapter` and enforce Pydantic parameter validation.
- **Fail-Closed Policy**: If any security control or audit store fails, execution must halt safely.
- **Never Commit Secrets**: Check your diffs before committing (`git diff`). Never commit `.env` or credential files.
- **Preserve Documentation**: Maintain docstrings, schema documentation, and update `docs/` when introducing architectural changes.
- **Pull Requests**:
  - Keep PRs focused on a single feature or fix.
  - Ensure 100% test pass rate on both unit and integration tests.
  - Follow the pull request template checklist.
