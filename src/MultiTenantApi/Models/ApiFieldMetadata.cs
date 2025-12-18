namespace MultiTenantApi.Models;

public sealed record ApiFieldMetadata(
    string PropertyName,
    string JsonName,
    bool Expose,
    bool IsIdentifier,
    bool IsSensitive,
    string? Masking,
    string? Description);
