using System;

namespace MultiTenantApi.Models;

[AttributeUsage(AttributeTargets.Property)]
public sealed class ApiFieldAttribute : Attribute
{
    public ApiFieldAttribute(
        string jsonName,
        bool expose = false,
        bool isIdentifier = false,
        bool isSensitive = false,
        string? masking = null,
        string? description = null)
    {
        JsonName = jsonName;
        Expose = expose;
        IsIdentifier = isIdentifier;
        IsSensitive = isSensitive;
        Masking = masking;
        Description = description;
    }

    /// <summary>JSON field name used in external payloads.</summary>
    public string JsonName { get; }

    /// <summary>Whether this field is allowed to be exposed to external consumers.</summary>
    public bool Expose { get; }

    /// <summary>Marks internal identifiers / key fields.</summary>
    public bool IsIdentifier { get; }

    /// <summary>Marks fields containing PII or other sensitive values.</summary>
    public bool IsSensitive { get; }

    /// <summary>Masking strategy label (e.g., "phone-last4", "synthetic-id").</summary>
    public string? Masking { get; }

    /// <summary>Human-readable description for metadata consumers.</summary>
    public string? Description { get; }
}
