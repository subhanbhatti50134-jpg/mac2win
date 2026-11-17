using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Mac2WinReceiver.Core;
using Xunit;

namespace Mac2WinReceiver.Core.Tests;

/// <summary>
/// Protocol conformance against the committed golden vectors (ADR-011).
/// These tests are AUTOMATED: real crypto, real files, no mocks, no network.
/// </summary>
public class VectorTests
{
    /// <summary>Locates the repo root (directory containing protocol/VERSION) from the test output dir.</summary>
    internal static string RepoRoot
    {
        get
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir is not null)
            {
                if (File.Exists(Path.Combine(dir.FullName, "protocol", "VERSION")))
                    return dir.FullName;
                dir = dir.Parent;
            }
            throw new InvalidOperationException("repo root not found from " + AppContext.BaseDirectory);
        }
    }

    internal static JsonDocument LoadVector(string name)
    {
        var path = Path.Combine(RepoRoot, "protocol", "vectors", name);
        return JsonDocument.Parse(File.ReadAllText(path));
    }

    // ---------------------------------------------------------------- pairing

    [Fact]
    public void PairingProof_MatchesGoldenTranscript()
    {
        using var doc = LoadVector("pairing_transcript.json");
        var r = doc.RootElement;
        var pin = r.GetProperty("pin").GetString()!;
        var fp = r.GetProperty("certFingerprintSha256").GetString()!;
        var serverNonce = r.GetProperty("serverNonceB64").GetString()!;
        var clientNonce = r.GetProperty("clientNonceB64").GetString()!;
        var pubkey = r.GetProperty("devicePublicKeyB64").GetString()!;
        var expectedKey = r.GetProperty("pinKeyHex").GetString()!;
        var expectedProof = r.GetProperty("pinProofHex").GetString()!;

        var pinKey = PairingProof.DerivePinKey(pin, fp);
        Assert.Equal(expectedKey, Convert.ToHexString(pinKey).ToLowerInvariant());

        var proof = PairingProof.ComputeProof(pin, fp, clientNonce, serverNonce, pubkey);
        Assert.Equal(expectedProof, Convert.ToHexString(proof).ToLowerInvariant());

        // negative: wrong PIN must fail
        Assert.False(PairingProof.Verify("000000", fp, clientNonce, serverNonce, pubkey, proof));
        // negative: tampered nonce must fail
        Assert.False(PairingProof.Verify(pin, fp, clientNonce, serverNonce + "x", pubkey, proof));
    }

    [Fact]
    public void DeviceAuthSignedMessage_MatchesGoldenTranscript()
    {
        using var doc = LoadVector("pairing_transcript.json");
        var r = doc.RootElement.GetProperty("deviceAuth");
        var expected = r.GetProperty("signedMessageUtf8").GetString()!;
        using var t = LoadVector("pairing_transcript.json");
        var clientNonce = t.RootElement.GetProperty("clientNonceB64").GetString()!;
        var serverNonce = t.RootElement.GetProperty("serverNonceB64").GetString()!;
        Assert.Equal(expected, $"{clientNonce}|{serverNonce}");
    }

    // ------------------------------------------------------------ manifest

    [Fact]
    public void ManifestDigest_MatchesGoldenVector()
    {
        using var doc = LoadVector("manifest_digest.json");
        var r = doc.RootElement;
        var entries = r.GetProperty("entries").EnumerateArray()
            .Select(ManifestDigest.ParseEntry).ToList();
        var expectedBytesHex = r.GetProperty("canonicalBytesHex").GetString()!;
        var expectedDigest = r.GetProperty("manifestDigest").GetString()!;

        var bytes = ManifestDigest.CanonicalBytes(entries);
        Assert.Equal(expectedBytesHex, Convert.ToHexString(bytes).ToLowerInvariant());
        Assert.Equal(expectedDigest, ManifestDigest.ComputeHex(entries));
    }

    // --------------------------------------------------------- chunk hashing

    [Fact]
    public void ChunkHashes_MatchDeterministicRecipe()
    {
        using var doc = LoadVector("chunk_hashes.json");
        var r = doc.RootElement;
        var seed = Encoding.ASCII.GetBytes(r.GetProperty("seed").GetString()!);

        foreach (var c in r.GetProperty("cases").EnumerateArray())
        {
            var size = c.GetProperty("size").GetInt64();
            var expected = c.GetProperty("sha256").GetString()!;
            var data = GenBytes(seed, (int)size);
            Assert.Equal(size, data.Length);
            Assert.Equal(expected, Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant());
        }

        var hello = Convert.FromHexString(r.GetProperty("hello").GetProperty("bytesHex").GetString()!);
        Assert.Equal(r.GetProperty("hello").GetProperty("sha256").GetString()!,
            Convert.ToHexString(SHA256.HashData(hello)).ToLowerInvariant());
        Assert.Equal(r.GetProperty("emptyFileSha256").GetString()!,
            Convert.ToHexString(SHA256.HashData(Array.Empty<byte>())).ToLowerInvariant());
    }

    [Fact]
    public void ChunkBoundaries_MathMatchesVector()
    {
        using var doc = LoadVector("chunk_hashes.json");
        var cb = doc.RootElement.GetProperty("chunkBoundaries");
        var chunkSize = cb.GetProperty("chunkSize").GetInt64();
        var fileSize = cb.GetProperty("fileSize").GetInt64();
        var expectedCount = cb.GetProperty("expectedChunkCount").GetInt32();
        var expectedSizes = cb.GetProperty("chunkSizes").EnumerateArray().Select(x => x.GetInt64()).ToArray();

        var count = fileSize == 0 ? 0 : (int)((fileSize + chunkSize - 1) / chunkSize);
        Assert.Equal(expectedCount, count);
        var sizes = Enumerable.Range(0, count)
            .Select(i => Math.Min(chunkSize, fileSize - i * chunkSize)).ToArray();
        Assert.Equal(expectedSizes, sizes);
    }

    internal static byte[] GenBytes(byte[] seed, int n)
    {
        using var ms = new MemoryStream(n);
        var counter = 0UL;
        var buf = new byte[8];
        while (ms.Length < n)
        {
            using var inc = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            inc.AppendData(seed);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(buf, counter); // uint64be, per recipe
            inc.AppendData(buf);
            var block = inc.GetHashAndReset();
            var toWrite = (int)Math.Min(block.Length, n - ms.Length);
            ms.Write(block, 0, toWrite);
            counter++;
        }
        return ms.ToArray();
    }

    // ----------------------------------------------------------- error table

    [Fact]
    public void ErrorTable_MatchesGoldenVector()
    {
        using var doc = LoadVector("error_responses.json");
        foreach (var c in doc.RootElement.GetProperty("cases").EnumerateArray())
        {
            var code = Enum.Parse<ErrorCode>(c.GetProperty("code").GetString()!);
            var status = c.GetProperty("httpStatus").GetInt32();
            var body = c.GetProperty("body").GetProperty("error");
            var message = body.GetProperty("message").GetString()!;
            var retryable = body.GetProperty("retryable").GetBoolean();

            var (expectedStatus, expectedRetryable) = ProtocolErrors.Table[code];
            Assert.Equal(status, (int)expectedStatus);
            Assert.Equal(retryable, expectedRetryable);

            // generated body must be byte-identical in shape and values
            var err = ProtocolErrors.Create(code, message);
            var json = JsonSerializer.Serialize(err.ToBody());
            using var parsed = JsonDocument.Parse(json);
            Assert.Equal(code.ToString(), parsed.RootElement.GetProperty("error").GetProperty("code").GetString());
            Assert.Equal(message, parsed.RootElement.GetProperty("error").GetProperty("message").GetString());
            Assert.Equal(retryable, parsed.RootElement.GetProperty("error").GetProperty("retryable").GetBoolean());
        }
    }

    [Fact]
    public void ErrorTable_CoversEveryEnumMember()
    {
        var enumNames = Enum.GetNames<ErrorCode>().ToHashSet();
        var tableNames = ProtocolErrors.Table.Keys.Select(c => c.ToString()).ToHashSet();
        Assert.Equal(enumNames, tableNames);
    }

    // ----------------------------------------------------------- path policy

    [Fact]
    public void PathSanitizer_MatchesGoldenVector()
    {
        using var doc = LoadVector("path_policy.json");
        foreach (var c in doc.RootElement.GetProperty("sanitize").EnumerateArray())
        {
            var input = c.GetProperty("input").GetString()!;
            var expectedVerdict = c.GetProperty("verdict").GetString()!;
            var result = PathSanitizer.Sanitize(input);

            switch (expectedVerdict)
            {
                case "ACCEPT":
                    Assert.Equal(PathSanitizer.Verdict.Accept, result.Verdict);
                    Assert.Equal(c.GetProperty("finalPath").GetString(), result.FinalPath);
                    break;
                case "SANITIZE":
                    Assert.Equal(PathSanitizer.Verdict.Sanitize, result.Verdict);
                    Assert.Equal(c.GetProperty("finalPath").GetString(), result.FinalPath);
                    break;
                case "REJECT":
                    Assert.Equal(PathSanitizer.Verdict.Reject, result.Verdict);
                    Assert.Equal(c.GetProperty("reason").GetString(), result.Reason);
                    break;
                default:
                    throw new InvalidOperationException("unknown verdict " + expectedVerdict);
            }
        }
    }

    [Fact]
    public void PolicyExclusions_MatchGoldenVector()
    {
        using var doc = LoadVector("path_policy.json");
        foreach (var c in doc.RootElement.GetProperty("exclusions").EnumerateArray())
        {
            var input = c.GetProperty("input").GetString()!;
            var expected = c.GetProperty("reason").GetString();
            Assert.Equal(expected, PathSanitizer.ExcludedPolicyReason(input));
        }
    }

    [Fact]
    public void NfcNormalization_MatchesGoldenVector()
    {
        using var doc = LoadVector("path_policy.json");
        foreach (var c in doc.RootElement.GetProperty("nfc").EnumerateArray())
        {
            var input = c.GetProperty("input").GetString()!;
            var expected = c.GetProperty("nfc").GetString()!;
            Assert.Equal(expected, PathSanitizer.ToNfc(input));
        }
    }

    [Fact]
    public void CaseCollisions_MatchGoldenVector()
    {
        using var doc = LoadVector("path_policy.json");
        foreach (var c in doc.RootElement.GetProperty("caseCollisions").EnumerateArray())
        {
            var a = c.GetProperty("a").GetString()!;
            var b = c.GetProperty("b").GetString()!;
            var expected = c.GetProperty("collide").GetBoolean();
            Assert.Equal(expected, PathSanitizer.Collides(a, b));
        }

        var example = doc.RootElement.GetProperty("caseCollisionRename").GetProperty("example");
        var order = example.GetProperty("inputOrder").EnumerateArray().Select(x => x.GetString()!).ToList();
        var expectedFinal = example.GetProperty("finalPaths").EnumerateArray().Select(x => x.GetString()!).ToList();
        Assert.Equal(expectedFinal, PathSanitizer.ResolveCaseCollisions(order));
    }
}
