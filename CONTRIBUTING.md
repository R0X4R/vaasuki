# Contributing to Vaasuki

First of all, thank you for considering contributing to **Vaasuki**! Contributions from the security research and open-source community are what make tools like this thrive.

## Code of Conduct & Attribution Ethics

Open-source software is built on collaboration, mutual respect, and transparency. 

> [!IMPORTANT]
> ### A Note on Intellectual Property & Attribution
> A tremendous amount of thought, research, engineering, and testing went into designing and building Vaasuki's architecture, service fingerprinting engine, and active verifiers.
>
> If you are inspired by this project, use its architecture, borrow code snippets, or adapt its core ideas for your own tools:
> * **Please give appropriate credit and link back to this original repository.**
> * **Do not copy, rebrand, or publish this work under your own name without proper attribution.**
> 
> Learning from and building upon each other's work is celebrated in open source—taking someone else's effort and claiming it as solely your own is not. Please respect fellow creators and honor the community spirit.


## How Can You Contribute?

### 1. Adding New Service Verifiers
We actively welcome new protocol verifiers under `lib/`. When contributing a new service module:
- Ensure handshakes are strictly **safe, non-destructive, and unauthenticated**.
- Never trigger state-altering operations (e.g. data deletion, account lockout, resource exhaustion).
- Include both vulnerable and hardened test configurations in `lab/docker-compose.yml`.
- Follow the existing finding model and ensure zero false positives against authenticated or hardened instances.

### 2. Reporting Bugs & Anomalies
- Use the GitHub Issues tracker to report bugs.
- Include the exact CLI invocation, command output with `-v` (verbose) enabled, target OS, and steps to reproduce.

### 3. Improving Performance & Fingerprinting
- PRs that optimize concurrency, reduce packet roundtrips, or improve wire-protocol signatures are always appreciated.


## Development Workflow

1. **Fork the Repository**:
   Create a personal fork of `github.com/R0X4R/vaasuki`.

2. **Create a Feature Branch**:
   ```bash
   git checkout -b feature/new-service-verifier
   ```

3. **Validate Code & Tests**:
   Before submitting your PR, ensure:
   - Code adheres to idiomatic Go conventions (`gofmt -s -w .`).
   - The test suite compiles and runs cleanly:
     ```bash
     go test ./...
     go build main.go
     ```

4. **Open a Pull Request**:
   Describe your changes clearly in the PR description, referencing any relevant issues or lab container tests.
