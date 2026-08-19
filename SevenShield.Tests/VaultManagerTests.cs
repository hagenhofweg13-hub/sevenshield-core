using SevenShield.Core;
using Xunit;

namespace SevenShield.Tests;

public class VaultManagerTests : IDisposable
{
    private readonly string _vaultDir;

    private static readonly Argon2Parameters FastTestParams = new()
    {
        MemorySizeKb = 8192,
        Iterations = 1,
        Parallelism = 1
    };

    public VaultManagerTests()
    {
        _vaultDir = Path.Combine(Path.GetTempPath(), "SevenShieldManagerTests_" + Guid.NewGuid());
        Directory.CreateDirectory(_vaultDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_vaultDir))
            Directory.Delete(_vaultDir, recursive: true);
    }

    private void CreateSampleTree()
    {
        File.WriteAllText(Path.Combine(_vaultDir, "Bericht.txt"), "Top-Level Inhalt äöü");

        var sub = Path.Combine(_vaultDir, "Unterordner");
        Directory.CreateDirectory(sub);
        File.WriteAllText(Path.Combine(sub, "Detail.txt"), "Inhalt im Unterordner");

        var subsub = Path.Combine(sub, "Tief");
        Directory.CreateDirectory(subsub);
        File.WriteAllText(Path.Combine(subsub, "SehrTief.txt"), "Noch tiefer verschachtelt");
    }

    [Fact]
    public void LockUnlock_Roundtrip_RestoresFullFolderStructure()
    {
        CreateSampleTree();

        var result = VaultManager.LockFolder(_vaultDir, "passwort123", FastTestParams);
        Assert.Equal(3, result.FileCount);
        Assert.True(VaultManager.IsLocked(_vaultDir));

        // Originaldateien müssen weg sein, nur Container + .sevenshield übrig.
        Assert.False(File.Exists(Path.Combine(_vaultDir, "Bericht.txt")));
        Assert.False(Directory.Exists(Path.Combine(_vaultDir, "Unterordner")));

        var unlockResult = VaultManager.UnlockFolder(_vaultDir, "passwort123");
        Assert.True(unlockResult.FullySuccessful);
        Assert.Equal(3, unlockResult.SuccessCount);
        Assert.False(VaultManager.IsLocked(_vaultDir));

        Assert.Equal("Top-Level Inhalt äöü", File.ReadAllText(Path.Combine(_vaultDir, "Bericht.txt")));
        Assert.Equal("Inhalt im Unterordner", File.ReadAllText(Path.Combine(_vaultDir, "Unterordner", "Detail.txt")));
        Assert.Equal("Noch tiefer verschachtelt", File.ReadAllText(Path.Combine(_vaultDir, "Unterordner", "Tief", "SehrTief.txt")));
    }

    [Fact]
    public void Unlock_WithWrongPassword_ThrowsBeforeTouchingContainers()
    {
        CreateSampleTree();
        VaultManager.LockFolder(_vaultDir, "richtig", FastTestParams);

        var containersBefore = Directory.GetFiles(_vaultDir, "*.7sv").Length;

        Assert.Throws<VaultCryptoException>(() => VaultManager.UnlockFolder(_vaultDir, "falsch"));

        // Nichts darf angerührt worden sein - Verifikation schlägt VOR dem Entschlüsseln fehl.
        Assert.True(VaultManager.IsLocked(_vaultDir));
        Assert.Equal(containersBefore, Directory.GetFiles(_vaultDir, "*.7sv").Length);
    }

    [Fact]
    public void LockFolder_AlreadyLocked_ThrowsVaultStateException()
    {
        CreateSampleTree();
        VaultManager.LockFolder(_vaultDir, "passwort", FastTestParams);

        Assert.Throws<VaultStateException>(() => VaultManager.LockFolder(_vaultDir, "passwort", FastTestParams));
    }

    [Fact]
    public void UnlockFolder_NotLocked_ThrowsVaultStateException()
    {
        CreateSampleTree();
        Assert.Throws<VaultStateException>(() => VaultManager.UnlockFolder(_vaultDir, "beliebig"));
    }

    [Fact]
    public void LockFolder_EmptyFolder_ThrowsVaultStateException()
    {
        Assert.Throws<VaultStateException>(() => VaultManager.LockFolder(_vaultDir, "passwort", FastTestParams));
    }

    [Fact]
    public void LockFolder_ContainerFileNamesRevealNothing()
    {
        CreateSampleTree();
        VaultManager.LockFolder(_vaultDir, "passwort", FastTestParams);

        var containerNames = Directory.GetFiles(_vaultDir, "*.7sv").Select(Path.GetFileNameWithoutExtension);
        foreach (var name in containerNames)
        {
            Assert.DoesNotContain("Bericht", name);
            Assert.DoesNotContain("Detail", name);
            Assert.DoesNotContain("Tief", name);
        }
    }

    [Fact]
    public void LockFolder_ReportsProgressForEachFile()
    {
        CreateSampleTree();
        var reports = new List<VaultProgress>();
        var progress = new Progress<VaultProgress>(p => reports.Add(p));

        VaultManager.LockFolder(_vaultDir, "passwort", FastTestParams, progress);

        // Progress-Callbacks können asynchron nachlaufen; kurz nachfassen reicht hier,
        // da Progress<T> synchron auf dem aufrufenden SynchronizationContext postet.
        Assert.True(reports.Count >= 3);
        Assert.Equal(3, reports.Last().Total);
    }
}
