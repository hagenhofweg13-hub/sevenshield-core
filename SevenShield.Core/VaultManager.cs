using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SevenShield.Core;

/// <summary>Fortschritts-Meldung für lang laufende Lock/Unlock-Operationen (UI-Progressbar).</summary>
public sealed record VaultProgress(int Completed, int Total, string CurrentItem);

/// <summary>Ergebnis eines erfolgreichen <see cref="VaultManager.LockFolder"/>-Aufrufs.</summary>
public sealed record VaultLockResult(int FileCount);

/// <summary>Ergebnis eines <see cref="VaultManager.UnlockFolder"/>-Aufrufs, inkl. etwaiger Teilfehler.</summary>
public sealed record VaultUnlockResult(int SuccessCount, IReadOnlyList<VaultUnlockFailure> Failures)
{
    public bool FullySuccessful => Failures.Count == 0;
}

/// <summary>Einzelner fehlgeschlagener Dateientschlüsselung innerhalb eines Unlock-Vorgangs.</summary>
public sealed record VaultUnlockFailure(string ContainerFile, string Reason);

/// <summary>
/// Wird geworfen, wenn eine Ordner-Operation aufgrund des Ordnerzustands nicht
/// ausgeführt werden kann (z. B. Sperren eines bereits gesperrten Ordners).
/// </summary>
public sealed class VaultStateException : Exception
{
    public VaultStateException(string message) : base(message) { }
}

/// <summary>
/// Persistente Metadaten eines gesperrten Ordners (liegt als <c>.sevenshield</c>
/// im Root des Ordners). Enthält NIE das Passwort selbst, nur einen Nachweis
/// (Salt + Hash eines separat abgeleiteten Verifikations-Schlüssels), mit dem
/// sich ein eingegebenes Passwort vor dem eigentlichen Entsperren prüfen lässt
/// — schnelles, verständliches Fehlschlagen statt N einzelner Krypto-Fehler.
/// </summary>
internal sealed class VaultFolderInfo
{
    public int FormatVersion { get; set; } = 1;
    public DateTime LockedAtUtc { get; set; }
    public string VerifierSaltBase64 { get; set; } = "";
    public string VerifierHashBase64 { get; set; } = "";
    public int Argon2MemorySizeKb { get; set; }
    public int Argon2Iterations { get; set; }
    public int Argon2Parallelism { get; set; }
    public int Argon2KeyLengthBytes { get; set; }

    [JsonIgnore]
    public Argon2Parameters Argon2Params => new()
    {
        MemorySizeKb = Argon2MemorySizeKb,
        Iterations = Argon2Iterations,
        Parallelism = Argon2Parallelism,
        KeyLengthBytes = Argon2KeyLengthBytes
    };
}

/// <summary>
/// Orchestriert <see cref="CryptoEngine"/> über einen gesamten Ordner (inkl.
/// Unterordner): Sperren verschlüsselt jede Datei einzeln in eine 7SV1-Container-
/// Datei mit zufälligem Namen (der Original-Dateiname UND die Ordnerstruktur
/// werden nur verschlüsselt im Container hinterlegt, nicht im Klartext-Dateisystem
/// sichtbar). Entsperren macht das rückgängig.
/// </summary>
public static class VaultManager
{
    private const string VaultInfoFileName = ".sevenshield";
    private const string ContainerExtension = ".7sv";
    private const int VerifierSaltSizeBytes = 16;

    /// <summary>Ist der Ordner aktuell gesperrt (enthält eine gültige .sevenshield-Datei)?</summary>
    public static bool IsLocked(string folderPath) => File.Exists(Path.Combine(folderPath, VaultInfoFileName));

    /// <summary>
    /// Sperrt einen Ordner: verschlüsselt alle enthaltenen Dateien (rekursiv, inkl.
    /// Unterordner) in 7SV1-Container mit zufälligen Namen und löscht anschließend
    /// die Originaldateien sowie nun leere Unterordner.
    ///
    /// Transaktional im Rahmen des Möglichen: Schlägt die Verschlüsselung EINER
    /// Datei fehl, werden bereits erzeugte Container wieder gelöscht und KEINE
    /// Originaldatei angetastet — der Ordner bleibt im ursprünglichen Zustand.
    /// </summary>
    /// <exception cref="VaultStateException">Ordner ist bereits gesperrt oder enthält keine Dateien.</exception>
    public static VaultLockResult LockFolder(string folderPath, string password, Argon2Parameters? parameters = null, IProgress<VaultProgress>? progress = null)
    {
        if (!Directory.Exists(folderPath))
            throw new DirectoryNotFoundException($"Ordner nicht gefunden: {folderPath}");
        if (IsLocked(folderPath))
            throw new VaultStateException("Ordner ist bereits gesperrt.");

        parameters ??= new Argon2Parameters();

        var sourceFiles = Directory.EnumerateFiles(folderPath, "*", SearchOption.AllDirectories)
            .Where(f => !Path.GetFileName(f).Equals(VaultInfoFileName, StringComparison.OrdinalIgnoreCase))
            .Where(f => !f.EndsWith(ContainerExtension, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (sourceFiles.Count == 0)
            throw new VaultStateException("Ordner enthält keine Dateien zum Sperren.");

        var createdContainers = new List<string>();

        try
        {
            for (var i = 0; i < sourceFiles.Count; i++)
            {
                var sourceFile = sourceFiles[i];
                var relativePath = Path.GetRelativePath(folderPath, sourceFile).Replace('\\', '/');
                progress?.Report(new VaultProgress(i, sourceFiles.Count, relativePath));

                // Container flach im Root ablegen (zufälliger Name) — sonst würde
                // die Unterordner-Struktur selbst (Anzahl/Größe der Zweige) auf dem
                // verschlüsselten Dateisystem sichtbar bleiben, obwohl Namen/Inhalt
                // geschützt sind. Die eigentliche relative Position steckt nur noch
                // verschlüsselt im Container (siehe EncryptFile logicalName).
                var containerPath = Path.Combine(folderPath, Guid.NewGuid().ToString("N") + ContainerExtension);
                CryptoEngine.EncryptFile(sourceFile, containerPath, password, parameters, logicalName: relativePath);
                createdContainers.Add(containerPath);
            }
        }
        catch
        {
            foreach (var container in createdContainers)
            {
                try { File.Delete(container); } catch { /* Best effort beim Rollback */ }
            }
            throw;
        }

        // Erst jetzt, nachdem ALLE Dateien erfolgreich verschlüsselt sind, Originale entfernen.
        foreach (var sourceFile in sourceFiles)
            SecureDeleteBestEffort(sourceFile);

        RemoveEmptySubdirectories(folderPath);

        var vaultInfo = BuildVaultInfo(password, parameters);
        WriteVaultInfo(folderPath, vaultInfo);

        progress?.Report(new VaultProgress(sourceFiles.Count, sourceFiles.Count, ""));
        return new VaultLockResult(sourceFiles.Count);
    }

    /// <summary>
    /// Entsperrt einen Ordner: prüft das Passwort gegen den hinterlegten Nachweis,
    /// entschlüsselt anschließend alle Container zurück an ihre ursprüngliche
    /// relative Position (inkl. Wiederherstellung der Unterordner-Struktur).
    ///
    /// Einzelne fehlgeschlagene Container (z. B. durch Beschädigung) brechen den
    /// Vorgang NICHT ab — sie werden gesammelt zurückgegeben und bleiben als
    /// Container liegen, damit nichts verloren geht. Die .sevenshield-Datei wird
    /// nur gelöscht, wenn alle Container erfolgreich entschlüsselt wurden.
    /// </summary>
    /// <exception cref="VaultStateException">Ordner ist nicht gesperrt.</exception>
    /// <exception cref="VaultCryptoException">Passwort stimmt nicht mit dem hinterlegten Nachweis überein.</exception>
    public static VaultUnlockResult UnlockFolder(string folderPath, string password, IProgress<VaultProgress>? progress = null)
    {
        if (!IsLocked(folderPath))
            throw new VaultStateException("Ordner ist nicht gesperrt.");

        var vaultInfo = ReadVaultInfo(folderPath);
        VerifyPassword(vaultInfo, password); // wirft VaultCryptoException bei falschem Passwort

        var containers = Directory.EnumerateFiles(folderPath, "*" + ContainerExtension, SearchOption.TopDirectoryOnly).ToList();

        var failures = new List<VaultUnlockFailure>();
        var succeeded = 0;

        for (var i = 0; i < containers.Count; i++)
        {
            var container = containers[i];
            progress?.Report(new VaultProgress(i, containers.Count, Path.GetFileName(container)));

            try
            {
                var (logicalName, plainContent) = CryptoEngine.DecryptToBytes(container, password);
                try
                {
                    var relativePath = SanitizeRelativePath(logicalName);
                    var targetPath = Path.Combine(folderPath, relativePath);
                    Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);
                    targetPath = GetUniqueFilePath(targetPath);
                    File.WriteAllBytes(targetPath, plainContent);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(plainContent);
                }

                File.Delete(container);
                succeeded++;
            }
            catch (VaultCryptoException ex)
            {
                failures.Add(new VaultUnlockFailure(Path.GetFileName(container), ex.Message));
            }
        }

        progress?.Report(new VaultProgress(containers.Count, containers.Count, ""));

        if (failures.Count == 0)
        {
            File.Delete(Path.Combine(folderPath, VaultInfoFileName));
        }

        return new VaultUnlockResult(succeeded, failures);
    }

    private static VaultFolderInfo BuildVaultInfo(string password, Argon2Parameters parameters)
    {
        var verifierSalt = RandomNumberGenerator.GetBytes(VerifierSaltSizeBytes);
        var verifierKey = CryptoEngine.DeriveKey(password, verifierSalt, parameters);
        try
        {
            var verifierHash = SHA256.HashData(verifierKey);
            return new VaultFolderInfo
            {
                LockedAtUtc = DateTime.UtcNow,
                VerifierSaltBase64 = Convert.ToBase64String(verifierSalt),
                VerifierHashBase64 = Convert.ToBase64String(verifierHash),
                Argon2MemorySizeKb = parameters.MemorySizeKb,
                Argon2Iterations = parameters.Iterations,
                Argon2Parallelism = parameters.Parallelism,
                Argon2KeyLengthBytes = parameters.KeyLengthBytes
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(verifierKey);
        }
    }

    private static void VerifyPassword(VaultFolderInfo info, string password)
    {
        var verifierSalt = Convert.FromBase64String(info.VerifierSaltBase64);
        var expectedHash = Convert.FromBase64String(info.VerifierHashBase64);

        var verifierKey = CryptoEngine.DeriveKey(password, verifierSalt, info.Argon2Params);
        try
        {
            var actualHash = SHA256.HashData(verifierKey);
            // Konstantzeit-Vergleich statt ==, um Timing-Seitenkanäle zu vermeiden.
            if (!CryptographicOperations.FixedTimeEquals(actualHash, expectedHash))
                throw new VaultCryptoException("Falsches Passwort.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(verifierKey);
        }
    }

    private static void WriteVaultInfo(string folderPath, VaultFolderInfo info)
    {
        var json = JsonSerializer.Serialize(info, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(Path.Combine(folderPath, VaultInfoFileName), json, Encoding.UTF8);
    }

    private static VaultFolderInfo ReadVaultInfo(string folderPath)
    {
        var json = File.ReadAllText(Path.Combine(folderPath, VaultInfoFileName), Encoding.UTF8);
        return JsonSerializer.Deserialize<VaultFolderInfo>(json)
            ?? throw new VaultCryptoException(".sevenshield-Datei ist beschädigt oder ungültig.");
    }

    /// <summary>
    /// Bestbemühte "sichere" Löschung: überschreibt die Datei einmal mit Zufallsdaten,
    /// bevor sie gelöscht wird. Kein Ersatz für professionelle Datenvernichtung —
    /// insbesondere auf SSDs (Wear-Leveling) keine Garantie, siehe Projektnotizen
    /// Abschnitt 5 ("Spuren entschlüsselter Daten"). Best effort, kein Show-Stopper,
    /// falls das Überschreiben aus irgendeinem Grund fehlschlägt.
    /// </summary>
    private static void SecureDeleteBestEffort(string filePath)
    {
        try
        {
            var length = new FileInfo(filePath).Length;
            if (length > 0)
            {
                using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Write);
                var buffer = RandomNumberGenerator.GetBytes((int)Math.Min(length, 1024 * 1024));
                long written = 0;
                while (written < length)
                {
                    var chunk = (int)Math.Min(buffer.Length, length - written);
                    stream.Write(buffer, 0, chunk);
                    written += chunk;
                }
                stream.Flush();
            }
        }
        catch
        {
            // Überschreiben ist ein Best-effort-Zusatz — wenn es fehlschlägt (z. B.
            // Datei read-only), wird trotzdem ganz normal gelöscht.
        }

        File.Delete(filePath);
    }

    private static void RemoveEmptySubdirectories(string rootFolderPath)
    {
        foreach (var dir in Directory.EnumerateDirectories(rootFolderPath, "*", SearchOption.AllDirectories)
                     .OrderByDescending(d => d.Length)) // tiefste zuerst
        {
            if (!Directory.EnumerateFileSystemEntries(dir).Any())
            {
                try { Directory.Delete(dir); } catch { /* Best effort */ }
            }
        }
    }

    /// <summary>
    /// Zerlegt einen entschlüsselten logischen Namen (kann '/'-getrennte Unterordner
    /// enthalten) in einzelne Segmente, verwirft ".."/leere Segmente und säubert
    /// jedes Segment einzeln von ungültigen Zeichen — Schutz vor Path-Traversal,
    /// falls eine Container-Datei manipuliert wurde und trotzdem einen gültigen
    /// Auth-Tag hätte (siehe auch CryptoEngine.SanitizeFileName).
    /// </summary>
    private static string SanitizeRelativePath(string logicalName)
    {
        var rawSegments = logicalName.Split('/', '\\');
        var cleanSegments = new List<string>();

        foreach (var raw in rawSegments)
        {
            if (string.IsNullOrWhiteSpace(raw) || raw == "." || raw == "..")
                continue;

            var segment = raw;
            foreach (var invalidChar in Path.GetInvalidFileNameChars())
                segment = segment.Replace(invalidChar, '_');

            if (!string.IsNullOrWhiteSpace(segment))
                cleanSegments.Add(segment);
        }

        return cleanSegments.Count == 0
            ? "entschluesselte_datei"
            : Path.Combine(cleanSegments.ToArray());
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
