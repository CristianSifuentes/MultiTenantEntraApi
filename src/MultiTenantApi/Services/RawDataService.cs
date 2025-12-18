using MultiTenantApi.Models;

namespace MultiTenantApi.Services;

public record PageResult<T>(IReadOnlyList<T> Items, string? NextToken);

public interface IRawDataService
{
    Task<PageResult<RawRecord>> QueryAsync(string? filter, string? nextToken, int take, CancellationToken ct);
}

public sealed class InMemoryRawDataService : IRawDataService
{
    private readonly List<RawRecord> _data;

    public InMemoryRawDataService()
    {
        _data = Enumerable.Range(0, 25000).Select(i => new RawRecord
        {
            InternalId = Guid.NewGuid(),
            CreatedAt = DateTimeOffset.UtcNow.AddMinutes(-i),
            Channel = i % 2 == 0 ? "web" : "mobile",
            Text = $"Message #{i}",
            UserInternalId = i % 3 == 0 ? $"user-{i % 10}" : null
        })
        .OrderByDescending(x => x.CreatedAt)
        .ToList();
    }

    public Task<PageResult<RawRecord>> QueryAsync(string? filter, string? nextToken, int take, CancellationToken ct)
    {
        IEnumerable<RawRecord> q = _data;

        if (!string.IsNullOrWhiteSpace(filter))
        {
            var f = filter.ToLowerInvariant();
            q = q.Where(x =>
                (x.Text ?? string.Empty).ToLowerInvariant().Contains(f) ||
                x.Channel.ToLowerInvariant().Contains(f));
        }

        var skip = 0;
        if (!string.IsNullOrEmpty(nextToken) && int.TryParse(nextToken, out var cursor))
        {
            skip = cursor;
        }

        var page = q.Skip(skip).Take(take).ToList();
        var next = (skip + page.Count) < q.Count() ? (skip + page.Count).ToString() : null;

        return Task.FromResult(new PageResult<RawRecord>(page, next));
    }
}
