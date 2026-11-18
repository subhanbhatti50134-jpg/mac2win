using System.Security.Cryptography;
using System.Text;

namespace Mac2WinReceiver.Core;

/// <summary>
/// Hostile-path defense for the Windows destination (SPEC §6.2, docs/SECURITY.md).
/// The exact accept/sanitize/reject behavior is pinned by
/// protocol/vectors/path_policy.json and must stay byte-identical with the
/// Python reference in tools/gen_vectors.py (the Swift sender uses the same vectors
/// for its local pre-checks).
/// </summary>
public static class PathSanitizer
{
    public enum Verdict { Accept, Sanitize, Reject }

    public readonly record struct Result(Verdict Verdict, string Value)
    {
        /// <summary>For Reject, Value is the reason code; otherwise the final relative path.</summary>
        public string Reason => Verdict == Verdict.Reject ? Value : string.Empty;
        public string FinalPath => Verdict == Verdict.Reject ? string.Empty : Value;
    }

    // '\' is a filename character on the wire ('/' is the only separator) and an invalid
    // Windows character — replacing it keeps `..\..\evil` from ever acting as traversal.
    private static readonly HashSet<char> InvalidChars = new("<>:\"|?*\\");
    private static readonly HashSet<string> Reserved = new(StringComparer.Ordinal)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    };

    private const int MaxComponentUtf16 = 255;
    private const int TruncateBudget = 246; // + '-' + 8 hex = 255

    public static Result Sanitize(string path)
    {
        if (string.IsNullOrEmpty(path))
            return new Result(Verdict.Reject, ""); // reference returns empty reason for empty input

        foreach (var c in path)
        {
            if (c < 0x20 || c == 0x7F)
                return new Result(Verdict.Reject, "CONTROL_CHARACTER");
        }

        if (path.StartsWith("\\\\", StringComparison.Ordinal))
            return new Result(Verdict.Reject, "UNC");
        if (path.StartsWith('\\') || path.StartsWith('/'))
            return new Result(Verdict.Reject, "ROOTED");
        if (path.Length >= 2 && path[1] == ':' && char.IsLetter(path[0]))
            return new Result(Verdict.Reject, "DRIVE_LETTER");

        var segments = path.Split('/');
        if (segments.Any(s => s == ".."))
            return new Result(Verdict.Reject, "PATH_TRAVERSAL");

        var original = segments;
        segments = segments.Where(s => s != ".").ToArray();
        if (segments.Length == 0)
            return new Result(Verdict.Reject, "EMPTY");
        if (segments.Length > ProtocolConstants.MaxPathDepth)
            return new Result(Verdict.Reject, "PATH_TOO_DEEP");

        var sanitized = segments.Select(SanitizeComponent).ToArray();
        var final = string.Join("/", sanitized);
        var changed = !sanitized.SequenceEqual(original, StringComparer.Ordinal);
        return new Result(changed ? Verdict.Sanitize : Verdict.Accept, final);
    }

    public static string SanitizeComponent(string comp)
    {
        // 1. invalid characters and control characters → '_'
        var chars = comp.ToCharArray();
        for (var i = 0; i < chars.Length; i++)
        {
            var c = chars[i];
            if (InvalidChars.Contains(c) || c < 0x20 || c == 0x7F)
                chars[i] = '_';
        }
        comp = new string(chars);

        // 2. trim trailing dots/spaces
        comp = comp.TrimEnd('.', ' ');
        if (comp.Length == 0)
            return "_";

        // 3. reserved device name (with or without extension), case-insensitive
        var dot = comp.IndexOf('.');
        var stem = dot >= 0 ? comp[..dot] : comp;
        if (Reserved.Contains(stem.ToUpperInvariant()))
            comp = dot >= 0 ? stem + "_" + comp[dot..] : stem + "_";

        // 4. over-long component: truncate to 246 UTF-16 units + '-' + sha256(comp)[:8]
        if (comp.Length > MaxComponentUtf16)
        {
            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(comp)))
                .ToLowerInvariant()[..8];
            var sb = new StringBuilder(TruncateBudget + 9);
            var used = 0;
            foreach (var c in comp)
            {
                if (used + 1 > TruncateBudget)
                    break;
                sb.Append(c);
                used++;
            }
            // never split a surrogate pair (Python reference truncates on code points)
            if (sb.Length > 0 && char.IsHighSurrogate(sb[^1]))
                sb.Length--;
            comp = sb + "-" + hash;
        }

        return comp;
    }

    /// <summary>Apple metadata policy (SPEC §5 EXCLUDED_BY_POLICY). Returns reason or null.</summary>
    public static string? ExcludedPolicyReason(string path)
    {
        var parts = path.Split('/');
        for (var i = 0; i < parts.Length; i++)
        {
            var seg = parts[i];
            if (seg == ".DS_Store") return "POLICY_DOT_DS_STORE";
            if (seg.StartsWith("._", StringComparison.Ordinal)) return "POLICY_APPLEDOUBLE";
            if (seg == ".Trashes") return "POLICY_TRASH";
            if (seg == ".fseventsd") return "POLICY_FSEVENTSD";
            if (seg == ".Spotlight-V100") return "POLICY_SPOTLIGHT";
            if (seg == ".TemporaryItems") return "POLICY_TEMPITEMS";
            if (seg == "__MACOSX" && i == 0) return "POLICY_MACOSX";
        }
        return null;
    }

    /// <summary>Unicode NFC normalization for the wire (SPEC §6.1).</summary>
    public static string ToNfc(string s) => s.Normalize(NormalizationForm.FormC);

    /// <summary>
    /// Case-insensitive collision detection after NFC: two paths collide when their
    /// NFC + lower-invariant forms are equal (protocol/vectors/path_policy.json → caseCollisions).
    /// Note: the Python reference uses str.casefold(); exotic folds (e.g. ß→ss) are
    /// deliberately excluded from the vectors until both sides implement them.
    /// </summary>
    public static bool Collides(string a, string b) =>
        ToNfc(a).ToLowerInvariant() == ToNfc(b).ToLowerInvariant();

    /// <summary>
    /// Deterministic conflict rename: second and later colliding entries get " (n)"
    /// before the extension, n starting at 2, in input order.
    /// </summary>
    public static IReadOnlyList<string> ResolveCaseCollisions(IReadOnlyList<string> pathsInOrder)
    {
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var result = new List<string>(pathsInOrder.Count);
        foreach (var p in pathsInOrder)
        {
            var candidate = p;
            if (used.Contains(candidate))
            {
                var n = 2;
                do
                {
                    candidate = InsertSuffix(p, n);
                    n++;
                } while (used.Contains(candidate));
            }
            used.Add(candidate);
            result.Add(candidate);
        }
        return result;
    }

    private static string InsertSuffix(string path, int n)
    {
        // suffix goes on the LAST path component, before its extension
        var slash = path.LastIndexOf('/');
        var dir = slash >= 0 ? path[..(slash + 1)] : string.Empty;
        var name = slash >= 0 ? path[(slash + 1)..] : path;
        var dot = name.LastIndexOf('.');
        // dot==0 means a dotfile like ".bashrc": no extension
        if (dot > 0)
            return dir + name[..dot] + $" ({n})" + name[dot..];
        return dir + name + $" ({n})";
    }
}
