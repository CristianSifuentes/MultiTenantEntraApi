namespace MultiTenantApi.Models;

public sealed class RawRecord
{
    // Internal key - never exposed
    public Guid InternalId { get; set; }

    [ApiField("timestamp", expose: true, description: "UTC timestamp when the record was created.")]
    public DateTimeOffset CreatedAt { get; set; }

    [ApiField("channel", expose: true, description: "Source channel (web, mobile, Teams, etc.).")]
    public string Channel { get; set; } = string.Empty;

    [ApiField("messageText", expose: true, isSensitive: false, description: "Message or event text.")]
    public string? Text { get; set; }

    [ApiField(
        "userId",
        expose: false,
        isIdentifier: true,
        isSensitive: true,
        masking: "synthetic-id",
        description: "Internal user identifier – replaced by synthetic IDs in external exports.")]
    public string? UserInternalId { get; set; }
}
