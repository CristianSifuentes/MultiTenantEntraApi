using System.Security.Cryptography;
using System.Text;

namespace MultiTenantApi.Models;

public static class SyntheticId
{
    // Replace with your own 32-byte random value (Base64) in real deployments
    private static readonly byte[] Salt =
        Convert.FromBase64String("V6Zg6mQJc4f8a4kD8cWlQv8pQvY2uX1a0n9d2oR3f6s=");

    public static string Create(params string[] parts)
    {
        using var hmac = new HMACSHA256(Salt);
        var payload = string.Join("|", parts);
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(payload));
        return Convert.ToHexString(hash);
    }
}
