namespace MultiTenantApi.Models;

public sealed class InMenu
{
    public int AutoAttendantId { get; set; }
    public int InteractionStatusId { get; set; }
    public double Duration { get; set; }
    public int InteractionId { get; set; }
    public string Skill { get; set; } = string.Empty;
    public DateTime StartDate { get; set; }
    public DateTime EndDate { get; set; }
    public int Id { get; set; }
    public string Oid { get; set; } = string.Empty;
    public int ClientId { get; set; }
    public int TenantId { get; set; }
}
