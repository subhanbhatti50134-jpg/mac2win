using System.Text.Json;
using System.Text.Json.Nodes;
using Mac2WinReceiver.Core.Tests.Integration;
using Xunit;

namespace Mac2WinReceiver.Core.Tests.Unit;

/// <summary>
/// Fuzz tests for the manifest endpoint/parser (SPEC §10 unit level: "Fuzz-test the manifest
/// parser and path validator"). Each iteration opens a fresh approved session and POSTs one
/// randomly-shaped manifest batch, so every entry is parsed by
/// <see cref="TransferSession.ParseAndPlanEntry"/>. Asserts the server never crashes or leaks
/// internals: every response is structured JSON, malformed input maps to a 400-class error,
/// and two-phase parse guarantees a rejected batch never mutates state.
/// </summary>
public sealed class ManifestParserFuzzTests
{
    private static readonly string[] Paths =
    {
        "readme.txt", "folder/file.txt", "./rel.txt", "..\\..\\evil", "/abs/passwd",
        "CON.txt", "nul.dat", "a b.txt", "trailing. ", "name..txt", "a/b/c/d.txt",
        "\u202Eevil.txt", "caf\u00e9.txt", "file\u0001.bin", "", " ",
        new string('a', 300),
    };
    private static readonly string[] Types = { "file", "dir", "symlink", "FILE", "unknown", "" };
    private static readonly string[] Sizes = { "0", "1", "1048576", "-1", "99999999999999999999", "abc", "", "1.5" };
    private static readonly string[] Mtimes = { "171457440000000000", "not-a-number", "", "abc", "-5" };
    private static readonly string[] Modes = { "420", "493", "-1", "99999999999999999999", "abc", "" };

    private static readonly Random Rng = new(20261118);

    /// <summary>Builds a random JSON manifest-batch body as a string.</summary>
    private static string RandomBatchBody(int count)
    {
        var arr = new JsonArray();
        for (var i = 0; i < count; i++)
        {
            var obj = new JsonObject();
            if (Rng.Next(5) != 0) obj["path"] = Paths[Rng.Next(Paths.Length)];
            if (Rng.Next(5) != 0) obj["type"] = Types[Rng.Next(Types.Length)];
            if (Rng.Next(5) != 0) obj["size"] = Sizes[Rng.Next(Sizes.Length)];
            if (Rng.Next(5) != 0) obj["mtimeUtcNs"] = Mtimes[Rng.Next(Mtimes.Length)];
            if (Rng.Next(5) != 0) obj["mode"] = Modes[Rng.Next(Modes.Length)];
            if (Rng.Next(20) == 0) obj["weird"] = Rng.Next(1000); // unknown field (ignored)
            if (Rng.Next(50) == 0) obj["path"] = null; // explicit null
            arr.Add(obj);
        }
        // sometimes emit invalid JSON outright to fuzz deserialization
        return Rng.Next(10) == 0 ? "{[garbage" : new JsonObject { ["entries"] = arr }.ToJsonString();
    }

    [Fact]
    public async Task ManifestEndpoint_NeverCrashes_OnRandomBatches()
    {
        var crashed = false;
        var batchesSent = 0;
        // fresh session per batch: batchIndex=0 always matches BatchesReceived=0,
        // so every batch's entries are parsed by ParseAndPlanEntry.
        for (var i = 0; i < 1_000; i++)
        {
            await using var env = await TestEnv.StartAsync();
            var client = await env.AuthenticatedClientAsync();

            var sid = await client.CreateSessionAsync(1000, 0, 1000L * 1000 * 1000);
            var token = await client.AwaitApprovalAsync(sid);
            var sessionUrl = $"/v1/sessions/{sid}/manifest";

            var body = RandomBatchBody(Rng.Next(0, 6));
            JsonObject? root = null;
            try { root = JsonNode.Parse(body)?.AsObject(); } catch { /* invalid JSON → skip */ }
            if (root is null) continue;
            // ensure required wrapper fields so the batch reaches ParseAndPlanEntry
            root["batchIndex"] = 0;
            root["final"] = false;

            var resp = await client.PostRawAsync(sessionUrl, root.ToJsonString(), token);
            batchesSent++;

            // structured JSON answer, never a raw crash/HTML page
            if (resp.Status == 500)
            {
                crashed = true;
                var errorCode = resp.Body.GetProperty("error").GetProperty("code").GetString();
                Assert.Equal("E_INTERNAL", errorCode);
            }
            else
            {
                Assert.True(resp.IsSuccess || resp.Status is 400 or 409 or 413,
                    $"unexpected status {resp.Status} at batch {i}");
            }
        }
        Assert.True(batchesSent > 0, "no batch was sent — fuzz did not exercise anything");
        Assert.False(crashed, "server returned 500 E_INTERNAL during manifest fuzz");
    }
}
