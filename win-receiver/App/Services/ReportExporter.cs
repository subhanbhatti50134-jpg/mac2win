using System.Text;
using System.Text.Json;
using Mac2WinReceiver.Core.Server;

namespace Mac2WinReceiver.App.Services;

/// <summary>Exportable report: JSON, CSV, HTML (SPEC §5).</summary>
public sealed class ReportExporter
{
    public string ExportJson(SessionReport report) =>
        JsonSerializer.Serialize(report, new JsonSerializerOptions(JsonSerializerDefaults.Web)
        { WriteIndented = true });

    public string ExportCsv(SessionReport report)
    {
        var sb = new StringBuilder();
        sb.AppendLine("sessionId,status,startedAt,finishedAt,items,verified,renamed,replaced,skipped,excluded,failed,bytesVerified");
        var t = report.Totals;
        sb.Append($"{report.SessionId},{report.Status},{report.StartedAt},{report.FinishedAt},");
        sb.Append($"{t.Items},{t.Verified},{t.Renamed},{t.Replaced},{t.Skipped},{t.Excluded},{t.Failed},{t.BytesVerified}");
        sb.AppendLine();
        sb.AppendLine("path,finalPath,outcome,size,fileSha256,reason,errorCode");
        foreach (var item in report.Items)
        {
            sb.Append($"\"{EscapeCsv(item.Path)}\",");
            sb.Append($"\"{EscapeCsv(item.FinalPath)}\",");
            sb.Append($"\"{EscapeCsv(item.Outcome)}\",");
            sb.Append($"{item.Size},");
            sb.Append($"\"{EscapeCsv(item.FileSha256)}\",");
            sb.Append($"\"{EscapeCsv(item.Reason)}\",");
            sb.Append($"\"{EscapeCsv(item.ErrorCode)}\"");
            sb.AppendLine();
        }
        return sb.ToString();
    }

    public string ExportHtml(SessionReport report)
    {
        var t = report.Totals;
        var rows = new StringBuilder();
        foreach (var item in report.Items)
        {
            rows.Append("<tr>");
            rows.Append($"<td>{HtmlEncode(item.Path)}</td>");
            rows.Append($"<td>{HtmlEncode(item.FinalPath)}</td>");
            rows.Append($"<td>{HtmlEncode(item.Outcome)}</td>");
            rows.Append($"<td>{item.Size}</td>");
            rows.Append($"<td>{HtmlEncode(item.FileSha256)}</td>");
            rows.Append($"<td>{HtmlEncode(item.Reason)}</td>");
            rows.Append($"<td>{HtmlEncode(item.ErrorCode)}</td>");
            rows.Append("</tr>");
        }
        return $$"""
        <!DOCTYPE html>
        <html><head><meta charset="utf-8"><title>Mac2Win Transfer Report</title>
        <style>body{font-family:Segoe UI,sans-serif;padding:24px}table{border-collapse:collapse;width:100%}
        th,td{border:1px solid #ccc;padding:6px;text-align:left}th{background:#eee}
        .totals{margin-top:24px;font-size:14px;color:#555}</style></head>
        <body>
        <h1>Mac2Win Transfer Report</h1>
        <p>Session: <b>{{report.SessionId}}</b> &nbsp; Status: <b>{{report.Status}}</b></p>
        <p>Started: {{report.StartedAt}} &nbsp; Finished: {{report.FinishedAt}}</p>
        <table>
        <thead><tr><th>Path</th><th>Final Path</th><th>Outcome</th><th>Size</th><th>SHA-256</th><th>Reason</th><th>Error</th></tr></thead>
        <tbody>{{rows}}</tbody>
        </table>
        <div class="totals">
        Items: {{t.Items}} | Verified: {{t.Verified}} | Renamed: {{t.Renamed}} | Replaced: {{t.Replaced}} |
        Skipped: {{t.Skipped}} | Excluded: {{t.Excluded}} | Failed: {{t.Failed}} | Bytes verified: {{t.BytesVerified}}
        </div>
        </body></html>
        """;
    }

    private static string EscapeCsv(string? s)
    {
        if (s is null) return string.Empty;
        var needsQuotes = s.IndexOfAny(new[] { '"', ',', '\n', '\r' }) >= 0;
        return needsQuotes
            ? "\"" + s.Replace("\"", "\"\"") + "\""
            : s;
    }

    private static string HtmlEncode(string? s) =>
        s is null ? string.Empty :
        s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
}
