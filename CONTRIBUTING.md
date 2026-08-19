# Contributing to SevenShield.Core

Thanks for your interest in contributing! This project is maintained
part-time, so please bear with me on response times.

## Before you start

For anything beyond a small fix (typos, minor bugs), please open an issue
first to discuss the change. This avoids wasted effort on pull requests that
might not align with the project's direction — especially for anything
touching the cryptographic core (`CryptoEngine.cs`, `VaultMetadata.cs`,
`VaultManager.cs`), where changes need extra scrutiny.

## Development setup

Requirements: .NET 8 SDK.

```
git clone https://github.com/hagenhofweg13-hub/sevenshield-core.git
cd sevenshield-core
dotnet restore
dotnet build
dotnet test
```

All tests should pass before you open a pull request. If you add new
behavior, please add corresponding tests in `SevenShield.Tests`.

## Pull requests

- Keep pull requests focused on a single change.
- Describe what the change does and why.
- Make sure `dotnet test` passes locally.
- For changes to cryptographic logic, please explain your reasoning in
  detail — these changes affect the security guarantees of the whole
  project and will be reviewed carefully.

## Reporting bugs

Please open a GitHub issue with steps to reproduce, expected vs. actual
behavior, and your .NET/OS version.

## Reporting security vulnerabilities

Please do **not** open a public issue for security vulnerabilities. See
[SECURITY.md](SECURITY.md) for how to report these responsibly.

## Code style

Follow the existing style in the codebase (standard C# conventions, clear
naming, XML doc comments on public members where helpful). No strict style
enforcement tool is configured yet — use your best judgment and keep it
consistent with surrounding code.

Thank you for helping improve SevenShield.Core!
