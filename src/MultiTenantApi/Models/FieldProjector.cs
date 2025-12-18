using System.Reflection;

namespace MultiTenantApi.Models;

public static class FieldProjector
{
    public static IDictionary<string, object?> ToApiShape<T>(T entity)
    {
        var dict = new Dictionary<string, object?>();

        foreach (var p in typeof(T).GetProperties(BindingFlags.Instance | BindingFlags.Public))
        {
            var meta = p.GetCustomAttribute<ApiFieldAttribute>();
            if (meta?.Expose == true)
            {
                dict[meta.JsonName] = p.GetValue(entity);
            }
        }

        return dict;
    }
}
