using System.Reflection;

namespace MultiTenantApi.Models;

public static class ApiMetadataBuilder
{
    public static IReadOnlyList<ApiFieldMetadata> BuildFor<T>()
    {
        var list = new List<ApiFieldMetadata>();

        foreach (var prop in typeof(T).GetProperties(BindingFlags.Instance | BindingFlags.Public))
        {
            var attr = prop.GetCustomAttribute<ApiFieldAttribute>();
            if (attr is null) continue;

            list.Add(new ApiFieldMetadata(
                PropertyName: prop.Name,
                JsonName: attr.JsonName,
                Expose: attr.Expose,
                IsIdentifier: attr.IsIdentifier,
                IsSensitive: attr.IsSensitive,
                Masking: attr.Masking,
                Description: attr.Description
            ));
        }

        return list;
    }
}
