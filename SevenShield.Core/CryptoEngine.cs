using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace SevenShield.Core;

/// <summary>
/// Parameter für die Argon2id-Schlüsselableitung.
/// Defaults orientieren sich an den OWASP-Empfehlungen für interaktive Anwendungen
/// (m=64 MiB, t=4, p=4) — ausreichend GPU-resistent, ohne die UI spürbar zu blockieren.
/// </summary>
public sealed record Argon2Parameters
{
    /// <summary>Speicherbedarf in KiB. 65536 = 64 MiB.</summary>
    public int MemorySizeKb { get; init; } = 65536;

    /// <summary>Anzahl der Durchläufe.</summary>
    public int Iterations { get; init; } = 4;

    /// <summary>Grad der Parallelität (Threads).</summary>
    public int Parallelism { get; init; } = 4;

    /// <summary>Länge des abgeleiteten Schlüssels in Bytes. 32 = AES-256.</summary>
    public int KeyLengthBytes { get; init; } = 32;
}

/// <summary>
/// Wird geworfen, wenn Entschlüsselung fehlschlägt — falsches Passwort oder
/// manipulierte/beschädigte Datei. AES-GCM liefert diese Garantie über den Auth-Tag.
/// </summary>
public sealed class VaultCryptoException : Exception
{
    public VaultCryptoException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>
/// Reine Krypto-Logik: Argon2id-Schlüsselableitung und AES-256-GCM
/// Verschlüsselung/Entschlüsselung einzelner Dateien inkl. Dateiname.
///
/// Bewusst UI- und Dateisystem-Layout-unabhängig gehalten (siehe VaultManager
/// für Ordner-Orchestrierung). Jede Methode ist zustandslos und thread-sicher,
/// solange keine gemeinsam genutzten Buffer übergeben werden.
/// </summary>
public static class CryptoEngine
{
    private const int SaltSizeBytes = 16;
    private const int NonceSizeBytes = 12;   // Standard-Nonce-Länge für AES-GCM
    private const int TagSizeBytes = 16;     // Volle 128-Bit-Authentifizierung

    /// <summary>
    /// Leitet aus einem Passwort und einem Salt einen 256-Bit-Schlüssel ab.
    /// Für jede Datei/jeden Ordner MUSS ein eigener, zufälliger Salt verwendet werden
    /// (siehe <see cref="GenerateSalt"/>) — sonst führen gleiche Passwörter zu gleichen Schlüsseln.
    /// </summary>
    public static byte[] DeriveKey(string password, byte[] salt, Argon2Parameters? parameters = null)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("Passwort darf nicht leer sein.", nameof(password));
        if (salt is null || salt.Length < SaltSizeBytes)
            throw new ArgumentException($"Salt muss mindestens {SaltSizeBytes} Bytes lang sein.", nameof(salt));

        parameters ??= new Argon2Parameters();
        var passwordBytes = Encoding.UTF8.GetBytes(password);

        try
        {
            using var argon2 = new Argon2id(passwordBytes)
            {
                Salt = salt,
                DegreeOfParallelism = parameters.Parallelism,
                Iterations = parameters.Iterations,
                MemorySize = parameters.MemorySizeKb
            };

            return argon2.GetBytes(parameters.KeyLengthBytes);
        }
        finally
        {
            // Passwort-Bytes aus dem Speicher tilgen, sobald sie nicht mehr gebraucht werden.
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    /// <summary>Erzeugt einen kryptografisch sicheren, zufälligen Salt.</summary>
    public static byte[] GenerateSalt() => RandomNumberGenerator.GetBytes(SaltSizeBytes);

    /// <summary>Erzeugt einen kryptografisch sicheren, zufälligen Nonce für AES-GCM.</summary>
    private static byte[] GenerateNonce() => RandomNumberGenerator.GetBytes(NonceSizeBytes);

    /// <summary>
    /// Verschlüsselt eine einzelne Datei inkl. ihres ursprünglichen Dateinamens.
    /// Erzeugt eine Container-Datei im 7SV1-Format (siehe VaultMetadata) unter
    /// <paramref name="outputFilePath"/>. Der Klartext-Dateiname wird NICHT auf
    /// Platte im Klartext hinterlegt.
    /// </summary>
    public static void EncryptFile(string inputFilePath, string outputFilePath, string password, Argon2Parameters? parameters = null, string? logicalName = null)
    {
        if (!File.Exists(inputFilePath))
            throw new FileNotFoundException("Eingabedatei nicht gefunden.", inputFilePath);

        parameters ??= new Argon2Parameters();
        var salt = GenerateSalt();
        var key = DeriveKey(password, salt, parameters);

        try
        {
            // logicalName erlaubt VaultManager, einen relativen Pfad (inkl. Unterordner)
            // statt nur des Dateinamens zu hinterlegen — Standardfall (Einzeldatei-
            // Verschlüsselung) bleibt unverändert beim reinen Dateinamen.
            var originalFileName = logicalName ?? Path.GetFileName(inputFilePath);
            var plainContent = File.ReadAllBytes(inputFilePath);
            var plainFileName = Encoding.UTF8.GetBytes(originalFileName);

            var contentNonce = GenerateNonce();
            var contentCipher = new byte[plainContent.Length];
            var contentTag = new byte[TagSizeBytes];

            var nameNonce = GenerateNonce();
            var nameCipher = new byte[plainFileName.Length];
            var nameTag = new byte[TagSizeBytes];

            using (var aesContent = new AesGcm(key, TagSizeBytes))
            {
                // Zwei unabhängige Verschlüsselungen (Inhalt / Dateiname) unter demselben
                // Schlüssel erfordern zwingend zwei unterschiedliche Nonces — sonst bricht
                // die GCM-Sicherheitsgarantie (Nonce-Reuse).
                aesContent.Encrypt(contentNonce, plainContent, contentCipher, contentTag);
            }

            using (var aesName = new AesGcm(key, TagSizeBytes))
            {
                aesName.Encrypt(nameNonce, plainFileName, nameCipher, nameTag);
            }

            var metadata = new VaultMetadata
            {
                Salt = salt,
                Argon2Params = parameters,
                ContentNonce = contentNonce,
                ContentTag = contentTag,
                FileNameNonce = nameNonce,
                FileNameTag = nameTag,
                EncryptedFileName = nameCipher
            };

            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outputFilePath))!);

            using var output = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);
            metadata.WriteTo(output);
            output.Write(contentCipher, 0, contentCipher.Length);

            CryptographicOperations.ZeroMemory(plainContent);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>
    /// Entschlüsselt eine 7SV1-Container-Datei. Die Datei wird im Zielordner
    /// unter ihrem ursprünglichen Dateinamen (ohne eventuelle Unterordner-Anteile
    /// aus <c>logicalName</c> — siehe <see cref="EncryptFile"/>) wiederhergestellt.
    /// Gibt den vollständigen Pfad der wiederhergestellten Datei zurück.
    ///
    /// Für Aufrufer, die den vollständigen logischen Namen (z. B. inkl. Unterordner,
    /// wie ihn VaultManager beim Ordner-Sperren hinterlegt) selbst auswerten wollen,
    /// siehe <see cref="DecryptToBytes"/>.
    /// </summary>
    /// <exception cref="VaultCryptoException">
    /// Falsches Passwort oder beschädigte/manipulierte Datei — GCM-Auth-Tag stimmt nicht.
    /// </exception>
    public static string DecryptFile(string inputFilePath, string outputDirectory, string password)
    {
        var (logicalName, plainContent) = DecryptToBytes(inputFilePath, password);
        try
        {
            var fileName = SanitizeFileName(logicalName);

            Directory.CreateDirectory(outputDirectory);
            var outputPath = GetUniqueFilePath(Path.Combine(outputDirectory, fileName));
            File.WriteAllBytes(outputPath, plainContent);
            return outputPath;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plainContent);
        }
    }

    /// <summary>
    /// Entschlüsselt eine 7SV1-Container-Datei und gibt den rohen logischen Namen
    /// (so wie bei <see cref="EncryptFile"/> übergeben — kann Unterordner-Anteile
    /// mit '/' enthalten) sowie den entschlüsselten Inhalt zurück, OHNE etwas auf
    /// Platte zu schreiben. Aufrufer ist für Sanitizing/Platzierung verantwortlich
    /// (siehe <see cref="VaultManager"/>, die hierüber die Ordnerstruktur wiederherstellt).
    /// </summary>
    /// <exception cref="VaultCryptoException">
    /// Falsches Passwort oder beschädigte/manipulierte Datei — GCM-Auth-Tag stimmt nicht.
    /// </exception>
    public static (string LogicalName, byte[] PlainContent) DecryptToBytes(string inputFilePath, string password)
    {
        if (!File.Exists(inputFilePath))
            throw new FileNotFoundException("Container-Datei nicht gefunden.", inputFilePath);

        using var input = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
        var metadata = VaultMetadata.ReadFrom(input);

        var key = DeriveKey(password, metadata.Salt, metadata.Argon2Params);

        try
        {
            // 1. Dateinamen entschlüsseln
            var plainFileNameBytes = new byte[metadata.EncryptedFileName.Length];
            try
            {
                using var aesName = new AesGcm(key, TagSizeBytes);
                aesName.Decrypt(metadata.FileNameNonce, metadata.EncryptedFileName, metadata.FileNameTag, plainFileNameBytes);
            }
            catch (CryptographicException ex)
            {
                throw new VaultCryptoException("Falsches Passwort oder beschädigte Datei (Dateiname konnte nicht entschlüsselt werden).", ex);
            }

            var logicalName = Encoding.UTF8.GetString(plainFileNameBytes);

            // 2. Inhalt entschlüsseln
            var contentLength = (int)(input.Length - input.Position);
            var cipherContent = new byte[contentLength];
            var read = input.Read(cipherContent, 0, contentLength);
            if (read != contentLength)
                throw new VaultCryptoException("Container-Datei ist unvollständig oder beschädigt.");

            var plainContent = new byte[contentLength];
            try
            {
                using var aesContent = new AesGcm(key, TagSizeBytes);
                aesContent.Decrypt(metadata.ContentNonce, cipherContent, metadata.ContentTag, plainContent);
            }
            catch (CryptographicException ex)
            {
                throw new VaultCryptoException("Falsches Passwort oder beschädigte Datei (Inhalt konnte nicht entschlüsselt werden).", ex);
            }

            return (logicalName, plainContent);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>
    /// Entfernt Pfad-Trenner und andere potenziell gefährliche Zeichen aus einem
    /// entschlüsselten Dateinamen, bevor er zum Schreiben auf Platte verwendet wird
    /// (Schutz vor Path-Traversal, falls eine Container-Datei manipuliert wurde und
    /// trotzdem — theoretisch — einen gültigen Auth-Tag hätte).
    /// </summary>
    private static string SanitizeFileName(string fileName)
    {
        var name = Path.GetFileName(fileName);
        foreach (var invalidChar in Path.GetInvalidFileNameChars())
            name = name.Replace(invalidChar, '_');
        return string.IsNullOrWhiteSpace(name) ? "entschluesselte_datei" : name;
    }

    private static string GetUniqueFilePath(string desiredPath)
    {
        if (!File.Exists(desiredPath))
            return desiredPath;

        var directory = Path.GetDirectoryName(desiredPath)!;
        var nameWithoutExt = Path.GetFileNameWithoutExtension(desiredPath);
        var ext = Path.GetExtension(desiredPath);

        var counter = 1;
        string candidate;
        do
        {
            candidate = Path.Combine(directory, $"{nameWithoutExt} ({counter}){ext}");
            counter++;
        } while (File.Exists(candidate));

        return candidate;
    }
}
