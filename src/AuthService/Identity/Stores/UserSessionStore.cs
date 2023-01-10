using System.Security.Claims;
using AuthService.EFCore;
using CommonLibrary.AspNetCore.Identity.Helpers;
using CommonLibrary.AspNetCore.Identity.Models;
using CommonLibrary.Utilities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Session;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Redis;

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
        await RenewAsync(key, ticket);
        return key;
    }
    
  
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
        using var scope = _services.BuildServiceProvider().CreateScope();
        var authDbContext = scope.ServiceProvider.GetService<UserDbContext>();
        var httpContextAccessor = scope.ServiceProvider.GetService<IHttpContextAccessor>();
        var httpContext = httpContextAccessor?.HttpContext;
        if (authDbContext != null && httpContext != null)
        {
            var user = await authDbContext.Users.Include(x=>x.UserSessions).ThenInclude(x=>x.Device).SingleOrDefaultAsync(x => x.Id.ToString() == ticket.Principal.FindFirstValue(ClaimTypes.NameIdentifier));
            if (user != null)
            {
                var existingSession = user.UserSessions.SingleOrDefault(x=>x.CacheKey == key);
                if (existingSession == null)
                {
                    var asymmetricKey = PSec.GenerateAsymmetricKeyPair();
                    var session = new UserSession
                    {
                        CreationDate = DateTimeOffset.Now,
                        ExpirationDate = ticket.Properties.ExpiresUtc,
                        CacheKey = key,
                        PrivateKey = asymmetricKey.PublicKey.Key.ToArray(),
                        PublicKey = asymmetricKey.SecretKey.Key.ToArray(),
                        AuthenticationTicket = SerializeToBytes(ticket)
                    };
                    var remoteIpAddress = httpContext.Connection.RemoteIpAddress;
                    var userAgent = httpContext.Request.Headers["User-Agent"];
                    if (!string.IsNullOrEmpty(userAgent))
                    {
                        var deviceHash = Hashing.GenerateMD5Hash($"{userAgent}.{remoteIpAddress}.{user.Id}");
                        var currentDevice = authDbContext.UserDevices.FirstOrDefault(x=>x.Hash == deviceHash);
                        if (currentDevice != null)
                        {
                            // Device already exists, create a new one.
                            session.Device = currentDevice;
                        }
                        else
                        {
                            var uaParser = UAParser.Parser.GetDefault();
                            Console.WriteLine(uaParser.ToString());
                            var clientInfo = uaParser.Parse(userAgent);
                            var device = new UserDevice
                            {
                                Id = default,
                                CreationDate = DateTimeOffset.Now,
                                Descriptor = null,
                                IpAddress = remoteIpAddress?.ToString(),
                                UserAgent = userAgent,
                                DeviceName = clientInfo.Device.Model,
                                DeviceType = clientInfo.UserAgent.Family,
                                DeviceModel = $"{clientInfo.UserAgent.Major}.{clientInfo.UserAgent.Minor}.{clientInfo.UserAgent.Patch}",
                                DeviceOs = clientInfo.OS.ToString(),
                                Hash = deviceHash,
                                IsSuspended = false,
                                SuspendedDate = default,
                                SuspendedBy = default,
                                IsDeleted = false,
                                DeletedDate = default,
                                DeletedBy = default
                            };
                            session.Device = device;
                            user.UserDevices.Add(device);
                        }
                    }
                    user.UserSessions.Add(session);
                    await authDbContext.SaveChangesAsync();
                    var sessionClaim = new Claim(UserClaimTypes.UserSessionId, session.Id.ToString());
                    ticket.Principal.AddIdentity(new ClaimsIdentity(new []{sessionClaim}));
                    var exp = DateTimeOffset.UtcNow.AddMinutes(5);
                    var token = Securoman.GenerateToken(
                        asymmetricKey,
                        ticket.Principal.Claims,
                        user.SecretKey,
                        session.Id, exp);
                    httpContext.Response.Cookies.Append("Identity.Token",
                        token, new CookieOptions
                        {
                            Expires = exp
                        });
                    byte[] ticketBytes = SerializeToBytes(ticket);
                    await _cache.SetAsync(key, ticketBytes, options);
                }
                else if (existingSession.IsDeleted)
                {
                    // Session already exists, if it's deleted then remove the key from cache
                    await RemoveAsync(key);
                }
                else
                {
                    byte[] ticketBytes = SerializeToBytes(ticket);
                    // Session already exists and is alive, so just update the expiration date.
                    if (expiresUtc.HasValue)
                    {
                        existingSession.ExpirationDate = (expiresUtc.Value);
                    }
                    existingSession.AuthenticationTicket = ticketBytes;
                    await authDbContext.SaveChangesAsync();
                    await _cache.SetAsync(key, ticketBytes, options);
                }
            }
        }else
        {
            throw new ApplicationException("AuthDbContext or HttpContextAccessor is null");
        }
    }

    // Request start
    public async Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        Console.WriteLine($"Retrieving!!");
        AuthenticationTicket ticket;
        byte[] bytes = null;
        bytes =  await _cache.GetAsync(key);
        if (bytes == null)
        {
            using var scope = _services.BuildServiceProvider().CreateScope();
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
                Console.WriteLine("Context is empty!");
            }
        }
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
                var userSession = await context.UserSessions.SingleOrDefaultAsync(x => x.CacheKey == key);
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
