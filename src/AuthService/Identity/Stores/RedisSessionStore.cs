using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Caching.Distributed;

namespace AuthService.Identity.Stores;

public class RedisSessionStore : ITicketStore
{
    private const string KeyPrefix = "AuthSessionStore-";
    private IDistributedCache cache;

    public RedisSessionStore(IDistributedCache cache)
    {
        this.cache = cache;
    }

    public async Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        var guid = Guid.NewGuid();
        var key = KeyPrefix + guid.ToString();
        await RenewAsync(key, ticket);
        return key;
    }

    public Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        var options = new DistributedCacheEntryOptions();
        var expiresUtc = ticket.Properties.ExpiresUtc;
        if (expiresUtc.HasValue)
        {
            options.SetAbsoluteExpiration(expiresUtc.Value);
        }
        byte[] val = SerializeToBytes(ticket);
        cache.Set(key, val, options);
        return Task.FromResult(0);
    }

    public Task<AuthenticationTicket> RetrieveAsync(string key)
    {
        AuthenticationTicket ticket;
        byte[] bytes = null;
        bytes = cache.Get(key);
        ticket = DeserializeFromBytes(bytes);
        return Task.FromResult(ticket);
    }

    public Task RemoveAsync(string key)
    {
        cache.Remove(key);
        return Task.FromResult(0);
    }

    private static byte[] SerializeToBytes(AuthenticationTicket source)
    {
        return TicketSerializer.Default.Serialize(source);
    }

    private static AuthenticationTicket DeserializeFromBytes(byte[] source)
    {
        return source == null ? null : TicketSerializer.Default.Deserialize(source);
    }
}