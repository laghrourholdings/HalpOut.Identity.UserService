using System.Security.Claims;
using AuthService.EFCore;
using AuthService.Identity.Managers;
using CommonLibrary.AspNetCore.Identity.Model;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Redis;
using ILogger = Serilog.ILogger;

namespace AuthService.Identity.Stores;

public class UserSessionStore : ITicketStore
{
    private const string KeyPrefix = "AuthSessionStore-";
    private IDistributedCache _cache;
    private readonly IServiceCollection _services;

    public UserSessionStore(RedisCacheOptions options, IServiceCollection services)
    {
        _cache = new RedisCache(options);
        _services = services;
    }

    public async Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        var guid = Guid.NewGuid();
        var key = KeyPrefix + guid.ToString();
        using (var scope = _services.BuildServiceProvider().CreateScope())
        {
            var authDbContext = scope.ServiceProvider.GetService<UserDbContext>();
            var logger = scope.ServiceProvider.GetService<ILogger>();
            Console.WriteLine("Storing!!");
            if (authDbContext != null)
            {
                var user = await authDbContext.Users.SingleOrDefaultAsync(x => x.Id == ticket.Principal.FindFirstValue(ClaimTypes.NameIdentifier));
                if (user != null)
                {
                    user.UserSessions.Add(new UserSession
                    {
                        Id = Guid.NewGuid(),
                        CreationDate = DateTimeOffset.Now,
                        ExpirationDate = ticket.Properties.ExpiresUtc,
                        Key = key,
                        RawAuthenticationTicket = SerializeToBytes(ticket)
                    });
                    //TODO; ADD device registration
                    await authDbContext.SaveChangesAsync();
                }
            }
            else
            {
                logger?.Error("SessionContext is null {}", ticket);
            }
            await RenewAsync(key, ticket);
            return key;
        }
    }
    
    // Request end
    public async Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        Console.WriteLine($"RenewAsync Key: {key}");
        foreach (var vary in ticket.Principal.Claims)
        {
            Console.WriteLine($"{vary.Type} : {vary.Value}");
        }
        var options = new DistributedCacheEntryOptions();
        var expiresUtc = ticket.Properties.ExpiresUtc;
        
        if (expiresUtc.HasValue)
        {
            options.SetAbsoluteExpiration(expiresUtc.Value);
        }
        byte[] val = SerializeToBytes(ticket);
        using (var scope = _services.BuildServiceProvider().CreateScope())
        {
            var context = scope.ServiceProvider.GetService<UserDbContext>();
            
            if (context != null)
            {
                var userSession = await context.UserSessions.SingleOrDefaultAsync(x => x.Key == key);
                if (userSession != null)
                {
                    await _cache.SetAsync(key, val, options);
                    userSession.RawAuthenticationTicket = val;
                    if (expiresUtc.HasValue)
                    {
                        userSession.ExpirationDate = expiresUtc;
                    }
                    context.UserSessions.Update(userSession);
                    await context.SaveChangesAsync();
                }
                else
                {
                    await RemoveAsync(key);
                }
            }
            else
            {
                Console.WriteLine("Context is empty!");
            }
        }
    }

    // Request start
    public async Task<AuthenticationTicket> RetrieveAsync(string key)
    {
        Console.WriteLine($"Retrieving!!");
        AuthenticationTicket ticket;
        byte[] bytes = null;
        bytes =  await _cache.GetAsync(key);
        ticket = DeserializeFromBytes(bytes);
        return ticket;
    }

    public async Task RemoveAsync(string key)
    {
        await _cache.RemoveAsync(key);
        using (var scope = _services.BuildServiceProvider().CreateScope())
        {
            var context = scope.ServiceProvider.GetService<UserDbContext>();
            if (context != null)
            {
                var userSession = await context.UserSessions.SingleOrDefaultAsync(x => x.Key == key);
                if (userSession != null)
                {
                    context.UserSessions.Remove(userSession);
                    await context.SaveChangesAsync();
                }
            }
            else
            {
                Console.WriteLine("Context is empty!");
            }
        }
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
