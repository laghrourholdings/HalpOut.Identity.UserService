using System.Net;
using System.Security.Claims;
using AuthService.Core;
using CommonLibrary.AspNetCore.Identity;
using CommonLibrary.Identity.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Redis;

namespace AuthService.Identity;

public class UserSessionStore : ITicketStore
{
    // Authenticated User Sessions Cache -
    private const string KeyPrefix = "AUSC-";
    private IDistributedCache _cache;
    private readonly IServiceCollection _services;

    public UserSessionStore(RedisCacheOptions options, IServiceCollection services)
    {
        _cache = new RedisCache(options);
        _services = services;
    }

    private async Task CreateSession(string key, AuthenticationTicket ticket)
    {
        using var scope = _services.BuildServiceProvider().CreateScope();
        var authDbContext = scope.ServiceProvider.GetService<UserDbContext>();
        var httpContextAccessor = scope.ServiceProvider.GetService<IHttpContextAccessor>();
        var httpContext = httpContextAccessor?.HttpContext;
        if (authDbContext == null) 
            throw new Exception("AuthDbContext is null");
        var user = await authDbContext.Users
            .Include(x=>x.UserSessions)
            .ThenInclude(x=>x.Device)
            .SingleOrDefaultAsync(x => x.Id.ToString() == ticket.Principal.FindFirstValue(UserClaimTypes.Id));
        if (user is null) return;
        var asymmetricKey = Pasetoman.GenerateAsymmetricKeyPair();
        var session = new UserSession
        {
            CreationDate = DateTimeOffset.Now,
            ExpirationDate = ticket.Properties.ExpiresUtc,
            CacheKey = key,
            PrivateKey = asymmetricKey.SecretKey.Key.ToArray(),
            PublicKey = asymmetricKey.PublicKey.Key.ToArray(),
            AuthenticationTicket = Pasetoman.SerializeToBytes(ticket)
        };
        var remoteIpAddress = (httpContext.Connection.RemoteIpAddress ?? IPAddress.Loopback).ToString();
        var userAgent = httpContext.Request.Headers["User-Agent"];
        var device = Deviceman.CreateDevice(userAgent, remoteIpAddress, user.Id);
        var currentDevice = authDbContext.UserDevices.FirstOrDefault(x=>x.Hash == device.Hash);
        if (currentDevice != null)
            session.Device = currentDevice;
        else
        {
            session.Device = device;
            user.UserDevices.Add(device);
        }
        user.UserSessions.Add(session);
        await authDbContext.SaveChangesAsync();
        
        
        var exp = DateTimeOffset.UtcNow.AddMinutes(5);
        var token = SecuromanTokenizer.GenerateToken(
            asymmetricKey,
            ticket.Principal.Claims,
            user.SecretKey,
            session.Id,
            exp);
        httpContext.Response.Cookies.Append(SecuromanDefaults.TokenCookie,
            token, new CookieOptions
            {
                Expires = new DateTimeOffset(2038, 1, 1, 0, 0, 0, TimeSpan.FromHours(0)),
                Secure = true
            });
        
        var options = new DistributedCacheEntryOptions();
        var expiresUtc = ticket.Properties.ExpiresUtc;
        if (expiresUtc.HasValue)
        {
            options.SetAbsoluteExpiration(expiresUtc.Value);
        }
        
        byte[] ticketBytes = Pasetoman.SerializeToBytes(ticket);
        await _cache.SetAsync(key, ticketBytes, options);
    }
    
    public async Task<string> StoreAsync(AuthenticationTicket rawTicket)
    {
        var key = KeyPrefix + Guid.NewGuid();
        await CreateSession(key, rawTicket);
        return key;
    }
    
  
    public async Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        byte[] ticketBytes = Pasetoman.SerializeToBytes(ticket);
        var options = new DistributedCacheEntryOptions();
        var expiresUtc = ticket.Properties.ExpiresUtc;
        if (expiresUtc.HasValue)
        {
            options.SetAbsoluteExpiration(expiresUtc.Value);
        }
        using var scope = _services.BuildServiceProvider().CreateScope();
        var httpContextAccessor = scope.ServiceProvider.GetService<IHttpContextAccessor>();
        var httpContext = httpContextAccessor?.HttpContext;
        var authDbContext = scope.ServiceProvider.GetService<UserDbContext>();
        var user = await authDbContext.Users
            .Include(x=>x.UserSessions)
            .ThenInclude(x=>x.Device)
            .SingleOrDefaultAsync(x => x.Id.ToString() == ticket.Principal.FindFirstValue(UserClaimTypes.Id));
        var session = user?.UserSessions.SingleOrDefault(x=>x.CacheKey == key);
        if (session != null) switch (session.IsDeleted)
        {
            case true:
                // Session already exists, if it's deleted then remove the key from cache
                await RemoveAsync(key);
                break;
            case false:
            {
                await _cache.SetAsync(key, ticketBytes, options);

                if (expiresUtc.HasValue)
                {
                    session.ExpirationDate = (expiresUtc.Value);
                }

                session.AuthenticationTicket = ticketBytes;
                await authDbContext.SaveChangesAsync();
                var exp = DateTimeOffset.UtcNow.AddMinutes(5);
                var asymmetricKey = Pasetoman.AsymmetricKeyPair(session.PrivateKey, session.PublicKey);
                var token = SecuromanTokenizer.GenerateToken(
                    asymmetricKey,
                    ticket.Principal.Claims,
                    user.SecretKey,
                    session.Id,
                    exp);
                httpContext.Response.Cookies.Append(SecuromanDefaults.TokenCookie,
                token, new CookieOptions
                    {
                        Expires = new DateTimeOffset(2038, 1, 1, 0, 0, 0, TimeSpan.FromHours(0)),
                        Secure = true
                    });
                break;
            }
        }
        else
        {
            await CreateSession(key, ticket);
        }
    }

    // Request start
    public async Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        var bytes = await _cache.GetAsync(key);
        if (bytes == null || bytes.Length == 0)
        { 
            using (var scope = _services.BuildServiceProvider().CreateScope())
            {
                var context = scope.ServiceProvider.GetService<UserDbContext>();
                if (context != null)
                {
                    var session = context.UserSessions.SingleOrDefault(x => x.CacheKey == key);
                    if (session?.ExpirationDate != null && session.IsDeleted == false)
                    {
                        var options = new DistributedCacheEntryOptions();
                        options.SetAbsoluteExpiration(session.ExpirationDate.Value);
                        await _cache.SetAsync(key, session.AuthenticationTicket, options);
                        bytes = session.AuthenticationTicket;
                    }else if (session?.IsDeleted == true)
                    {
                        context.UserSessions.Remove(session);
                        await context.SaveChangesAsync();
                    }
                }
                else
                {
                    throw new NullReferenceException("UserDbContext is null");
                }
            }
        }
        var ticket = Pasetoman.DeserializeFromBytes(bytes);
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
                var userSession = await context.UserSessions.SingleOrDefaultAsync(x => x.CacheKey == key);
                if (userSession != null)
                {
                    context.UserSessions.Remove(userSession);
                    await context.SaveChangesAsync();
                }
            }
            else
            {
                throw new NullReferenceException("UserDbContext is null");
            }
        }
    }

    
}
