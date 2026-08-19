using SevenShield.Core;
using Xunit;

namespace SevenShield.Tests;

public class CryptoEngineTests : IDisposable
{
    private readonly string _workDir;

    // Für Tests bewusst niedrige Argon2-Parameter, damit die Suite in Sekunden
    // statt Minuten läuft. Produktivbetrieb nutzt die Defaults aus Argon2Parameters.
    private static readonly Argon2Parameters FastTestParams = new()
    {
        MemorySizeKb = 8192,
        Iterations = 1,
        Parallelism = 1
    };

    public CryptoEngineTests()
    {
        _workDir = Path.Combine(Path.GetTempPath(), "SevenShieldTests_" + Guid.NewGuid());
        Directory.CreateDirectory(_workDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_workDir))
            Directory.Delete(_workDir, recursive: true);
    }

    [Fact]
    public void EncryptDecrypt_Roundtrip_RestoresOriginalContentAndFileName()
    {
        var original = Path.Combine(_workDir, "Prüfbericht CalOCrete 905.txt");
        var content = "Vertraulicher Testinhalt mit Umlauten: äöüß – RWE / CalOCrete";
        File.WriteAllText(original, content);

        var container = Path.Combine(_workDir, "container.7sv");
        CryptoEngine.EncryptFile(original, container, "korrektesPasswort!", FastTestParams);

        var outputDir = Path.Combine(_workDir, "out");
        var restoredPath = CryptoEngine.DecryptFile(container, outputDir, "korrektesPasswort!");

        Assert.Equal("Prüfbericht CalOCrete 905.txt", Path.GetFileName(restoredPath));
        Assert.Equal(content, File.ReadAllText(restoredPath));
    }

    [Fact]
    public void Decrypt_WithWrongPassword_ThrowsVaultCryptoException()
    {
        var original = Path.Combine(_workDir, "geheim.txt");
        File.WriteAllText(original, "Inhalt");

        var container = Path.Combine(_workDir, "container.7sv");
        CryptoEngine.EncryptFile(original, container, "richtig", FastTestParams);

        Assert.Throws<VaultCryptoException>(() =>
            CryptoEngine.DecryptFile(container, Path.Combine(_workDir, "out"), "falsch"));
    }

    [Fact]
    public void Decrypt_TamperedContent_ThrowsVaultCryptoException()
    {
        var original = Path.Combine(_workDir, "geheim.txt");
        File.WriteAllText(original, "Inhalt der manipuliert wird");

        var container = Path.Combine(_workDir, "container.7sv");
        CryptoEngine.EncryptFile(original, container, "passwort", FastTestParams);

        // Ein Byte am Ende der Datei (= im verschlüsselten Inhalt) kippen.
        var bytes = File.ReadAllBytes(container);
        bytes[^1] ^= 0xFF;
        File.WriteAllBytes(container, bytes);

        Assert.Throws<VaultCryptoException>(() =>
            CryptoEngine.DecryptFile(container, Path.Combine(_workDir, "out"), "passwort"));
    }

    [Fact]
    public void Decrypt_NonVaultFile_ThrowsVaultCryptoException()
    {
        var fakeContainer = Path.Combine(_workDir, "keinvault.7sv");
        File.WriteAllBytes(fakeContainer, new byte[] { 1, 2, 3, 4, 5 });

        Assert.Throws<VaultCryptoException>(() =>
            CryptoEngine.DecryptFile(fakeContainer, Path.Combine(_workDir, "out"), "beliebig"));
    }

    [Fact]
    public void EncryptDecrypt_EmptyFile_Works()
    {
        var original = Path.Combine(_workDir, "leer.txt");
        File.WriteAllBytes(original, Array.Empty<byte>());

        var container = Path.Combine(_workDir, "container.7sv");
        CryptoEngine.EncryptFile(original, container, "passwort", FastTestParams);

        var restoredPath = CryptoEngine.DecryptFile(container, Path.Combine(_workDir, "out"), "passwort");
        Assert.Empty(File.ReadAllBytes(restoredPath));
    }

    [Fact]
    public void Encrypt_SamePlaintextTwice_ProducesDifferentCiphertext()
    {
        // Zufälliger Salt + zufälliger Nonce pro Aufruf -> auch identischer
        // Klartext mit identischem Passwort muss unterschiedliche Container ergeben.
        var original = Path.Combine(_workDir, "gleich.txt");
        File.WriteAllText(original, "immer derselbe Inhalt");

        var container1 = Path.Combine(_workDir, "c1.7sv");
        var container2 = Path.Combine(_workDir, "c2.7sv");
        CryptoEngine.EncryptFile(original, container1, "passwort", FastTestParams);
        CryptoEngine.EncryptFile(original, container2, "passwort", FastTestParams);

        Assert.NotEqual(File.ReadAllBytes(container1), File.ReadAllBytes(container2));
    }

    [Fact]
    public void DeriveKey_SamePasswordAndSalt_IsDeterministic()
    {
        var salt = CryptoEngine.GenerateSalt();
        var key1 = CryptoEngine.DeriveKey("passwort", salt, FastTestParams);
        var key2 = CryptoEngine.DeriveKey("passwort", salt, FastTestParams);

        Assert.Equal(key1, key2);
    }

    [Fact]
    public void DeriveKey_DifferentSalt_ProducesDifferentKey()
    {
        var key1 = CryptoEngine.DeriveKey("passwort", CryptoEngine.GenerateSalt(), FastTestParams);
        var key2 = CryptoEngine.DeriveKey("passwort", CryptoEngine.GenerateSalt(), FastTestParams);

        Assert.NotEqual(key1, key2);
    }
}
