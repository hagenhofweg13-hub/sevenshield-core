# SevenShield.Core

The cryptographic core of **SevenShield**, a Windows folder encryption tool
built for small offices — law firms, medical practices, engineering offices,
and labs — that need straightforward, strong encryption for sensitive local
data.

This repository contains only the core cryptographic engine and vault logic.
It is UI-independent, MIT-licensed, and open for review, so that anyone
relying on it can inspect exactly how it works.

> The closed-source Windows UI application (`SevenShield.App`) is not part of
> this repository.

## What's inside

- **`CryptoEngine.cs`** — Argon2id key derivation, AES-256-GCM encryption and
  decryption of individual files (both content and filename are encrypted).
- **`VaultMetadata.cs`** — the binary container format (`FVL1`) used for
  encrypted files.
- **`VaultManager.cs`** — orchestrates `CryptoEngine` across an entire folder:
  recursive locking (including subfolders) and unlocking, password
  verification without ever storing the plaintext password, and a
  `.sevenshield` metadata file per vault.
- **`SevenShield.Tests`** — xUnit tests covering `CryptoEngine` and
  `VaultManager`: round-trip encryption, wrong-password handling, tampering /
  auth-tag verification, empty files, key-derivation determinism, folder
  round-trips including nested subfolders, and state-error handling.

## How it works

### Locking a folder (`LockFolder`)

1. Recursively finds all files in the target folder, including subfolders.
2. Encrypts each file individually via `CryptoEngine.EncryptFile` into a
   container file with a random name (`<guid>.7sv`), stored flat at the
   folder root. The file's original relative path (e.g.
   `subfolder/file.txt`) is encrypted along with it as a `logicalName`,
   rather than left visible on disk — otherwise the folder structure itself
   (subfolder count and depth) would remain observable even though names and
   contents are protected.
3. Only once *all* files have been successfully encrypted are the originals
   deleted (best-effort single overwrite) and empty subfolders removed. If
   encryption fails partway through, the containers created so far are
   removed again and the folder is left in its original state.
4. Writes a `.sevenshield` metadata file (JSON) containing a password proof:
   its own salt, its own Argon2 derivation, and a SHA-256 hash of that. The
   actual password itself is never stored anywhere.

### Unlocking a folder (`UnlockFolder`)

1. Checks the entered password against the `.sevenshield` proof first
   (constant-time comparison) — this gives a fast, clear failure instead of
   N individual decryption failures per file.
2. Decrypts each container back to its original relative path (subfolders
   are recreated).
3. Individual corrupted containers do **not** abort the whole operation —
   they're collected and returned as `Failures`, and remain on disk as
   containers (nothing is lost). `.sevenshield` is only deleted once every
   container has been successfully decrypted.
4. Both methods optionally accept an `IProgress<VaultProgress>` (file index,
   total count, current file name) for driving a progress bar in a UI.

## Container format (FVL1)

See the comment header in `VaultMetadata.cs` for the full layout. In short:
magic bytes, version, salt, Argon2 parameters, a separate nonce+tag for the
filename and for the content (two nonces are needed since both are encrypted
under the same derived key, and nonce reuse breaks the GCM security
guarantee), the length of the encrypted filename, the encrypted filename
itself, then the rest of the file as encrypted content.

## Security notes

- **Password handling**: password bytes are explicitly zeroed
  (`CryptographicOperations.ZeroMemory`) after key derivation, as is the
  derived key once it's no longer needed. .NET `string` cannot be securely
  wiped from memory (strings are immutable) — if this matters for your use
  case, using `SecureString`/`char[]` at the UI layer would be the natural
  next step; this is a UI-layer concern, not a `Core` one.
- **Path traversal protection**: `SanitizeFileName` prevents a decrypted
  filename containing `../` or similar from escaping the target folder if a
  container file were tampered with (defense in depth — the auth tag already
  prevents this in practice).
- **Argon2 parameters** (default): 64 MiB memory, 4 iterations, parallelism 4
  (OWASP recommendation for interactive applications). Adjust via
  `Argon2Parameters` if you need to tune unlock latency for your target
  hardware.
- **Not yet handled**: very large files are currently loaded entirely into
  memory (fine for documents/reports, not ideal for e.g. large video
  backups). A streaming mode would be a separate future addition, since
  `AesGcm` in .NET 8 doesn't directly support chunked processing of
  arbitrarily large streams.

## Building

Requirements: .NET 8 SDK and internet access to nuget.org (for
`Konscious.Security.Cryptography.Argon2`).

```
git clone https://github.com/hagenhofweg13-hub/sevenshield-core.git
cd sevenshield-core
dotnet restore
dotnet build
dotnet test
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md) — please do not
open a public issue for security-related findings.

## License

MIT — see [LICENSE](LICENSE).
