namespace MultiTenantApi.Models;

public sealed class CallRecordExportDto
{
    public string SyntheticCallId { get; set; } = default!;

    public string CallDirection { get; set; } = default!;
    public string Type { get; set; } = default!;
    public bool Accepted { get; set; }
    public bool Missed { get; set; }
    public bool Abandoned { get; set; }

    public DateTime EndTime { get; set; }
    public double QueueTime { get; set; }
    public double TalkTime { get; set; }
    public double CallTime { get; set; }

    public string Skill { get; set; } = string.Empty;

    public string? AnsweredByAlias { get; set; }
    public string? NotHandledByAlias { get; set; }

    public string CallerNumberMasked { get; set; } = string.Empty;
}
