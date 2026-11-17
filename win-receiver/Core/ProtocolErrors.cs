using System.Net;

namespace Mac2WinReceiver.Core;

/// <summary>
/// Normative error-code table (protocol/PROTOCOL.md §5). The HTTP status and the
/// retryable flag are part of the wire contract and are pinned by
/// protocol/vectors/error_responses.json.
/// </summary>
public enum ErrorCode
{
    E_BAD_REQUEST,
    E_UNSUPPORTED_VERSION,
    E_UNAUTHORIZED,
    E_NOT_PAIRED,
    E_PIN_INVALID,
    E_PIN_EXPIRED,
    E_PIN_LOCKED,
    E_APPROVAL_DENIED,
    E_SESSION_NOT_FOUND,
    E_SESSION_EXPIRED,
    E_SESSION_STATE,
    E_MANIFEST_TOO_LARGE,
    E_LIMIT_EXCEEDED,
    E_PATH_REJECTED,
    E_CONFLICT_UNRESOLVED,
    E_CHUNK_HASH_MISMATCH,
    E_FILE_HASH_MISMATCH,
    E_SOURCE_CHANGED,
    E_INSUFFICIENT_STORAGE,
    E_DESTINATION_ERROR,
    E_RATE_LIMITED,
    E_IDLE_TIMEOUT,
    E_INTERNAL,
}

public sealed record ProtocolError(ErrorCode Code, string Message, bool Retryable, HttpStatusCode Status)
{
    /// <summary>Wire body for every non-2xx response (protocol §5).</summary>
    public object ToBody() => new
    {
        error = new
        {
            code = Code.ToString(),
            message = Message,
            retryable = Retryable,
        },
    };
}

public static class ProtocolErrors
{
    /// <summary>code → (HTTP status, retryable), normative.</summary>
    public static IReadOnlyDictionary<ErrorCode, (HttpStatusCode Status, bool Retryable)> Table { get; } =
        new Dictionary<ErrorCode, (HttpStatusCode, bool)>
        {
            [ErrorCode.E_BAD_REQUEST] = (HttpStatusCode.BadRequest, false),
            [ErrorCode.E_UNSUPPORTED_VERSION] = (HttpStatusCode.BadRequest, false),
            [ErrorCode.E_UNAUTHORIZED] = (HttpStatusCode.Unauthorized, true),
            [ErrorCode.E_NOT_PAIRED] = (HttpStatusCode.Forbidden, false),
            [ErrorCode.E_PIN_INVALID] = (HttpStatusCode.Forbidden, true),
            [ErrorCode.E_PIN_EXPIRED] = (HttpStatusCode.Forbidden, false),
            [ErrorCode.E_PIN_LOCKED] = (HttpStatusCode.TooManyRequests, true),
            [ErrorCode.E_APPROVAL_DENIED] = (HttpStatusCode.Forbidden, false),
            [ErrorCode.E_SESSION_NOT_FOUND] = (HttpStatusCode.NotFound, false),
            [ErrorCode.E_SESSION_EXPIRED] = (HttpStatusCode.Gone, false),
            [ErrorCode.E_SESSION_STATE] = (HttpStatusCode.Conflict, true),
            [ErrorCode.E_MANIFEST_TOO_LARGE] = (HttpStatusCode.RequestEntityTooLarge, false),
            [ErrorCode.E_LIMIT_EXCEEDED] = (HttpStatusCode.RequestEntityTooLarge, false),
            [ErrorCode.E_PATH_REJECTED] = (HttpStatusCode.BadRequest, false),
            [ErrorCode.E_CONFLICT_UNRESOLVED] = (HttpStatusCode.Conflict, false),
            [ErrorCode.E_CHUNK_HASH_MISMATCH] = (HttpStatusCode.UnprocessableEntity, true),
            [ErrorCode.E_FILE_HASH_MISMATCH] = (HttpStatusCode.UnprocessableEntity, false),
            [ErrorCode.E_SOURCE_CHANGED] = (HttpStatusCode.Conflict, true),
            [ErrorCode.E_INSUFFICIENT_STORAGE] = (HttpStatusCode.InsufficientStorage, true),
            [ErrorCode.E_DESTINATION_ERROR] = (HttpStatusCode.InternalServerError, false),
            [ErrorCode.E_RATE_LIMITED] = (HttpStatusCode.TooManyRequests, true),
            [ErrorCode.E_IDLE_TIMEOUT] = (HttpStatusCode.RequestTimeout, true),
            [ErrorCode.E_INTERNAL] = (HttpStatusCode.InternalServerError, true),
        };

    public static ProtocolError Create(ErrorCode code, string message)
    {
        var (status, retryable) = Table[code];
        return new ProtocolError(code, message, retryable, status);
    }
}
