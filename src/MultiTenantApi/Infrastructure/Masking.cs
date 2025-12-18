namespace MultiTenantApi.Infrastructure;

public static class Masking
{
    public static string? MaskPhone(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var digits = new string(raw.Where(char.IsDigit).ToArray());
        if (digits.Length < 4) return "****";

        var last4 = digits[^4..];
        return $"***-***-{last4}";
    }

    public static string? MaskAgentName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return null;
        var trimmed = name.Trim();
        if (trimmed.Length <= 2) return "Agent";
        return $"Agent {trimmed[0]}."; // e.g. "Agent T."
    }
}
