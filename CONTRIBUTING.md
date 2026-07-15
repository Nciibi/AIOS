# Contributing to AIOS

Thank you for your interest in contributing to AIOS — the deterministic, security-first execution environment for LLM-generated actions.

## Code of Conduct

By participating in this project, you agree to maintain a respectful, constructive, and inclusive environment for everyone.

## Getting Started

1. Fork the repository.
2. Clone your fork:
   ```bash
   git clone https://github.com/your-username/aios.git
   cd aios
   ```
3. Build the workspace:
   ```bash
   cargo build --workspace
   ```
4. Run the tests:
   ```bash
   cargo test --workspace
   ```

## Project Structure

AIOS is a Rust workspace with six crates:

| Crate | Role |
|---|---|
| `aios-core` | Foundational types, traits, and primitives |
| `aios-intent` | Semantic parsing and validation of LLM output |
| `aios-context-resolver` | State binding, path resolution, injection scanning |
| `aios-policy` | Zero-trust policy evaluation and risk assessment |
| `aios-execution` | Sandboxed, audited safe execution |
| `aios-integration-tests` | End-to-end pipeline and chaos tests |

## How to Contribute

### Reporting Bugs

- Open a [GitHub Issue](https://github.com/aios-project/aios/issues/new).
- Include: OS version, Rust version (`rustc --version`), and a minimal reproduction.
- Label the issue with `bug`.

### Suggesting Features

- Open a [GitHub Issue](https://github.com/aios-project/aios/issues/new).
- Describe the problem you're solving, not just the solution.
- Label with `enhancement`.

### Submitting Pull Requests

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feat/my-change
   ```
2. Make your changes. Follow the existing code style — no tab characters, 4-space indentation.
3. Run `cargo clippy --workspace` and fix any warnings.
4. Run `cargo test --workspace` and ensure all tests pass.
5. Write tests for new functionality. We use `proptest`, `tempfile`, and `criterion` for property-based and integration tests.
6. Keep pull requests focused — one change per PR.
7. Update documentation if your change affects public APIs or behavior.

### Security Considerations

AIOS is a **security-critical** system. Please follow these guidelines:

- **No unsafe code** unless absolutely necessary and reviewed by two maintainers.
- **Fail-closed**: default-deny logic for all security checks.
- **No filesystem access in policy or intent layers** — only the executor mutates state.
- **Cryptographic decisions** must be deterministic and auditable.

### Commit Style

We use conventional commits:

```
feat: add capability for network namespace isolation
fix: resolve TOCTOU race in path resolver
docs: update pipeline architecture diagram
test: add chaos test for executor crash recovery
```

## Development Workflow

1. Run `cargo check --workspace` after every change.
2. Run integration tests for pipeline-level changes:
   ```bash
   cargo test --test '*' --workspace
   ```
3. For security-sensitive changes, run the attack simulation suite:
   ```bash
   cargo test attack_simulation --workspace
   ```

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
