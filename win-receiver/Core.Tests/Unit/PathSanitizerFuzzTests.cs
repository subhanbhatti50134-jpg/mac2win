using Mac2WinReceiver.Core;
using Xunit;

namespace Mac2WinReceiver.Core.Tests.Unit;

/// <summary>
/// Property/fuzz tests for the hostile-path validator (SPEC §10 unit level:
/// "path sanitizer — property-based and fuzz"). 20,000 seeded hostile inputs assert:
/// no exceptions, deterministic results, rejection reasons drawn only from the known
/// policy set, canonicalized containment inside the destination root, and idempotence
/// (an already-sanitized path is accepted unchanged).
/// </summary>
public sealed class PathSanitizerFuzzTests
{
    private static readonly string[] Fragments =
    {
        "..", ".", "...", "a", "file.txt", "CON", "con.txt", "PRN", "com1", "lpt9.dat",
        "x:y", "p?q", "a*b", "c<d", "e>f", "g|h", "i\"j", "nul", "aux", "COM0", "LPT1",
        "..\\..", "..\\..\\windows", "a\\b", "\\\\srv\\share", "C:", "C:/Windows", "/abs",
        "\\root", "trailing. ", "  leading", ".. ", " ... ", "tab\there", "bel\u0007x",
        "nul\u0000x", "\U0001F600", "caf\u00E9", "cafe\u0301", "\u202Eevil",
        "\u200Bzw", new string('x', 300), "", " ", ".. ", ".DS_Store", "._hidden",
        "deep/../../up", "name.", "name ", ".txt", "..txt", "a/b",
    };

    private static readonly HashSet<string> KnownRejectReasons = new(StringComparer.Ordinal)
    {
        "", "CONTROL_CHARACTER", "UNC", "ROOTED", "DRIVE_LETTER", "PATH_TRAVERSAL",
        "EMPTY", "PATH_TOO_DEEP",
    };

    private static string RandomPath(Random rng)
    {
        var deep = rng.Next(10) == 0; // deliberately exceed the depth cap sometimes
        var count = deep ? rng.Next(65, 75) : rng.Next(0, 12);
        var parts = new string[count];
        for (var i = 0; i < count; i++)
            parts[i] = Fragments[rng.Next(Fragments.Length)];
        // deep paths must use the real wire separator to reach the depth check
        var separator = deep || rng.Next(2) == 0 ? "/" : "\\";
        return string.Join(separator, parts);
    }

    private static string Show(string s) =>
        string.Concat(s.Select(c => c < 0x20 || c > 0x7E ? $"\\u{(int)c:X4}" : c.ToString()));

    [Fact]
    public void SeededFuzz_20000HostilePaths_NoThrow_Containment_Determinism_Idempotence()
    {
        var rng = new Random(20261118);
        var root = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "m2w-fuzz-dest"));
        var rootPrefix = root.EndsWith(Path.DirectorySeparatorChar)
            ? root
            : root + Path.DirectorySeparatorChar;

        for (var i = 0; i < 20_000; i++)
        {
            var input = RandomPath(rng);

            PathSanitizer.Result result;
            PathSanitizer.Result again;
            try
            {
                result = PathSanitizer.Sanitize(input);
                again = PathSanitizer.Sanitize(input);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException(
                    $"Sanitize threw for input [{Show(input)}]: {ex.Message}", ex);
            }

            Assert.Equal(result, again); // determinism

            if (result.Verdict == PathSanitizer.Verdict.Reject)
            {
                Assert.Contains(result.Reason, KnownRejectReasons); // known policy only
                continue;
            }

            var final = result.FinalPath;

            // containment: the canonicalized final path must stay inside the destination
            var combined = Path.GetFullPath(
                Path.Combine(root, final.Replace('/', Path.DirectorySeparatorChar)));
            Assert.True(combined.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase),
                $"input [{Show(input)}] escaped as [{Show(final)}]");

            // idempotence: sanitizing an already-sanitized path is a no-op (ACCEPT)
            var second = PathSanitizer.Sanitize(final);
            Assert.Equal(PathSanitizer.Verdict.Accept, second.Verdict);
            Assert.Equal(final, second.FinalPath);
        }
    }

    [Fact]
    public void DepthBoundary_64SegmentsAccepted_65Rejected()
    {
        var ok = string.Join('/', Enumerable.Repeat("seg", 64));
        Assert.Equal(PathSanitizer.Verdict.Accept, PathSanitizer.Sanitize(ok).Verdict);

        var tooDeep = string.Join('/', Enumerable.Repeat("seg", 65));
        var result = PathSanitizer.Sanitize(tooDeep);
        Assert.Equal(PathSanitizer.Verdict.Reject, result.Verdict);
        Assert.Equal("PATH_TOO_DEEP", result.Reason);
    }

    [Fact]
    public void BackslashTraversal_IsInert()
    {
        foreach (var input in new[]
                 {
                     @"..\..\evil.dll", @"..\..\..\..\x", @"folder\name.txt",
                     @"deep\..\..\y", // no drive prefix: backslash is a plain char here
                 })
        {
            var result = PathSanitizer.Sanitize(input);
            Assert.Equal(PathSanitizer.Verdict.Sanitize, result.Verdict);
            Assert.DoesNotContain('\\', result.FinalPath);
            Assert.DoesNotContain(result.FinalPath.Split('/'), s => s is ".." or ".");
        }

        // a drive-prefixed backslash path is rejected outright (DRIVE_LETTER), never escaped
        var drive = PathSanitizer.Sanitize(@"C:\Users\x");
        Assert.Equal(PathSanitizer.Verdict.Reject, drive.Verdict);
        Assert.Equal("DRIVE_LETTER", drive.Reason);
    }

    [Fact]
    public void ControlCharacters_RejectTheWholePath()
    {
        for (var c = 0; c <= 0x1F; c++)
        {
            var result = PathSanitizer.Sanitize($"dir/sub{(char)c}name.txt");
            Assert.Equal(PathSanitizer.Verdict.Reject, result.Verdict);
            Assert.Equal("CONTROL_CHARACTER", result.Reason);
        }
        var del = PathSanitizer.Sanitize("dir/sub\u007Fname.txt");
        Assert.Equal(PathSanitizer.Verdict.Reject, del.Verdict);
        Assert.Equal("CONTROL_CHARACTER", del.Reason);
    }

    [Fact]
    public void ReservedDeviceNames_AreRenamedNotRejected()
    {
        var reserved = new[] { "CON", "PRN", "AUX", "NUL" }
            .Concat(Enumerable.Range(0, 10).Select(i => $"COM{i}"))
            .Concat(Enumerable.Range(0, 10).Select(i => $"LPT{i}"))
            .ToList();

        foreach (var name in reserved)
        {
            foreach (var suffix in new[] { "", ".txt", ".DAT" })
            {
                var result = PathSanitizer.Sanitize(name + suffix);
                Assert.Equal(PathSanitizer.Verdict.Sanitize, result.Verdict);
                Assert.StartsWith(name + "_", result.FinalPath, StringComparison.Ordinal);

                var lower = name.ToLowerInvariant() + suffix;
                var lowerResult = PathSanitizer.Sanitize(lower);
                Assert.Equal(PathSanitizer.Verdict.Sanitize, lowerResult.Verdict);
                Assert.StartsWith(name.ToLowerInvariant() + "_", lowerResult.FinalPath,
                    StringComparison.Ordinal);

                // renamed output is stable under a second pass
                Assert.Equal(PathSanitizer.Verdict.Accept,
                    PathSanitizer.Sanitize(result.FinalPath).Verdict);
            }
        }
    }

    [Fact]
    public void HostileShapes_ReceiveTheDocumentedVerdict()
    {
        var cases = new (string Input, PathSanitizer.Verdict Verdict, string Value)[]
        {
            ("../../etc/passwd", PathSanitizer.Verdict.Reject, "PATH_TRAVERSAL"),
            ("/etc/passwd", PathSanitizer.Verdict.Reject, "ROOTED"),
            ("\\\\server\\share\\x", PathSanitizer.Verdict.Reject, "UNC"),
            ("C:/Windows/evil.dll", PathSanitizer.Verdict.Reject, "DRIVE_LETTER"),
            ("c:relative.txt", PathSanitizer.Verdict.Reject, "DRIVE_LETTER"),
            ("", PathSanitizer.Verdict.Reject, ""),
            ("a\u0001b", PathSanitizer.Verdict.Reject, "CONTROL_CHARACTER"),
            (string.Join('/', Enumerable.Repeat("x", 100)),
                PathSanitizer.Verdict.Reject, "PATH_TOO_DEEP"),
            ("good/file.txt", PathSanitizer.Verdict.Accept, "good/file.txt"),
            ("./rel/path.txt", PathSanitizer.Verdict.Sanitize, "rel/path.txt"),
        };

        foreach (var (input, verdict, value) in cases)
        {
            var result = PathSanitizer.Sanitize(input);
            Assert.Equal(verdict, result.Verdict);
            if (verdict == PathSanitizer.Verdict.Reject)
                Assert.Equal(value, result.Reason);
            else
                Assert.Equal(value, result.FinalPath);
        }
    }
}
