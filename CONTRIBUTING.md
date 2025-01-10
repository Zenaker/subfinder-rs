# Contributing to subfinder-rs

First off, thanks for taking the time to contribute! 🚀

## Getting Started

1. Fork the repository
2. Clone your fork:
```bash
git clone https://github.com/Zenaker/subfinder-rs.git
```

3. Create a new branch:
```bash
git checkout -b feature/amazing-feature
```

4. Make your changes
5. Run tests:
```bash
cargo test
```

6. Format code:
```bash
cargo fmt
```

7. Run clippy:
```bash
cargo clippy
```

## Pull Request Process

1. Update the README.md with details of changes if needed
2. Update any documentation that might be affected
3. Make sure all tests pass and there are no clippy warnings
4. Create a Pull Request with a clear description of the changes

## Code Style

- Follow Rust standard formatting (enforced by `rustfmt`)
- Use meaningful variable names
- Comment complex logic
- Write tests for new features
- Keep functions focused and small
- Use Rust idioms and best practices

## Adding New Sources

When adding a new source:

1. Create a new file in `src/sources/`
2. Implement the source trait
3. Add error handling
4. Add tests
5. Register the source in `mod.rs`
6. Document the source in README.md

## Commit Messages

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Reference issues and pull requests liberally after the first line

## Questions?

Feel free to open an issue for any questions or concerns.

-Zen
