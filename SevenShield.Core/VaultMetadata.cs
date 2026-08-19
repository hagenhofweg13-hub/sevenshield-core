using System;
using System.IO;
using System.Text;

namespace SevenShield.Core;

/// <summary>
/// Binäres Header-Format einer 7SV1-Container-Datei (eine verschlüsselte Datei).
///
/// Layout (little-endian, alles außer dem Inhalt ist Klartext-Metadaten):
///
///   4 Bytes   Magic               "7SV1"
///   1 Byte    Version             0x01
///   16 Bytes  Salt                Argon2id-Salt (pro Datei zufällig)
///   4 Bytes   Argon2 MemorySizeKb Int32
///   4 Bytes   Argon2 Iterations   Int32
///   4 Bytes   Argon2 Parallelism  Int32
///   12 Bytes  ContentNonce        AES-GCM-Nonce für den Dateiinhalt
///   16 Bytes  ContentTag          AES-GCM-Auth-Tag für den Dateiinhalt
///   12 Bytes  FileNameNonce       AES-GCM-Nonce für den Dateinamen
///   16 Bytes  FileNameTag         AES-GCM-Auth-Tag für den Dateinamen
///   4 Bytes   FileNameCipherLen   Int32 — Länge des verschlüsselten Dateinamens
///   N Bytes   EncryptedFileName   Verschlüsselter Dateiname (UTF-8, vor Verschlüsselung)
///   ...       EncryptedContent    Restliche Datei = verschlüsselter Inhalt
///
/// Salt, Nonces und der Auth-Tag sind bewusst Klartext im Header: das ist bei
/// AES-GCM üblich und notwendig (der Empfänger braucht sie, um überhaupt
/// entschlüsseln zu können) und schwächt die Sicherheit nicht.
/// </summary>
public sealed class VaultMetadata
{
    private static readonly byte[] MagicBytes = Encoding.ASCII.GetBytes("7SV1");
    private const byte FormatVersion = 0x01;

    public required byte[] Salt { get; init; }
    public required Argon2Parameters Argon2Params { get; init; }
    public required byte[] ContentNonce { get; init; }
    public required byte[] ContentTag { get; init; }
    public required byte[] FileNameNonce { get; init; }
    public required byte[] FileNameTag { get; init; }
    public required byte[] EncryptedFileName { get; init; }

    /// <summary>Schreibt den Header (nicht den Dateiinhalt) in einen Stream.</summary>
    public void WriteTo(Stream stream)
    {
        using var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true);

        writer.Write(MagicBytes);
        writer.Write(FormatVersion);

        writer.Write(Salt);
        writer.Write(Argon2Params.MemorySizeKb);
        writer.Write(Argon2Params.Iterations);
        writer.Write(Argon2Params.Parallelism);

        writer.Write(ContentNonce);
        writer.Write(ContentTag);
        writer.Write(FileNameNonce);
        writer.Write(FileNameTag);

        writer.Write(EncryptedFileName.Length);
        writer.Write(EncryptedFileName);
    }

    /// <summary>
    /// Liest den Header von einem Stream. Der Stream-Cursor steht danach am
    /// Anfang des verschlüsselten Dateiinhalts.
    /// </summary>
    public static VaultMetadata ReadFrom(Stream stream)
    {
        using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);

        var magic = reader.ReadBytes(4);
        if (!magic.AsSpan().SequenceEqual(MagicBytes))
            throw new VaultCryptoException("Keine gültige SevenShield-Datei (Magic-Bytes fehlen oder falsch).");

        var version = reader.ReadByte();
        if (version != FormatVersion)
            throw new VaultCryptoException($"Nicht unterstützte Container-Version: {version}.");

        var salt = reader.ReadBytes(16);
        var memorySizeKb = reader.ReadInt32();
        var iterations = reader.ReadInt32();
        var parallelism = reader.ReadInt32();

        var contentNonce = reader.ReadBytes(12);
        var contentTag = reader.ReadBytes(16);
        var fileNameNonce = reader.ReadBytes(12);
        var fileNameTag = reader.ReadBytes(16);

        var fileNameCipherLen = reader.ReadInt32();
        if (fileNameCipherLen < 0 || fileNameCipherLen > 4096)
            throw new VaultCryptoException("Ungültige Länge des verschlüsselten Dateinamens — Datei vermutlich beschädigt.");
        var encryptedFileName = reader.ReadBytes(fileNameCipherLen);

        return new VaultMetadata
        {
            Salt = salt,
            Argon2Params = new Argon2Parameters
            {
                MemorySizeKb = memorySizeKb,
                Iterations = iterations,
                Parallelism = parallelism
            },
            ContentNonce = contentNonce,
            ContentTag = contentTag,
            FileNameNonce = fileNameNonce,
            FileNameTag = fileNameTag,
            EncryptedFileName = encryptedFileName
        };
    }
}
