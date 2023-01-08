using System.Security.Claims;
using AuthService.EFCore;
using CommonLibrary.AspNetCore.Identity.Helpers;
using CommonLibrary.AspNetCore.Identity.Models;
using CommonLibrary.Utilities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
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
        using (var scope = _services.BuildServiceProvider().CreateScope())
        {
            var authDbContext = scope.ServiceProvider.GetService<UserDbContext>();
            var httpContextAccessor = scope.ServiceProvider.GetService<IHttpContextAccessor>();
            var httpContext = httpContextAccessor?.HttpContext;
            if (authDbContext != null && httpContext != null)
            {
                var user = await authDbContext.Users.Include(x=>x.UserSessions).SingleOrDefaultAsync(x => x.Id == ticket.Principal.FindFirstValue(ClaimTypes.NameIdentifier));
                if (user != null)
                {
                    var _session = authDbContext.UserSessions.Include(x=>x.Device).SingleOrDefault(x=>x.CacheKey == key);
                    if (_session == null)
                    {
                        var newSession = new UserSession
                        {
                            CreationDate = DateTimeOffset.Now,
                            ExpirationDate = ticket.Properties.ExpiresUtc,
                            CacheKey = key
                        };
                        var remoteIpAddress = httpContext.Connection.RemoteIpAddress;
                        var userAgent = httpContext.Request.Headers["User-Agent"];
                        if (!string.IsNullOrEmpty(userAgent))
                        {
                            var deviceHash = Hashing.GenerateMD5Hash($"{userAgent}.{remoteIpAddress}.{user.Id}");
                            var currentDevice = authDbContext.UserDevices.FirstOrDefault(x=>x.Hash == deviceHash);
                            if (currentDevice != null)
                            {
                                newSession.Device = currentDevice;
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
                                newSession.Device = device;
                            }
                        }
                        user.UserSessions.Add(newSession);
                        await authDbContext.SaveChangesAsync();
                        var session = authDbContext.UserSessions.SingleOrDefault(x=>x.CacheKey == key);
                        if (session != null)
                        {
                            var asymmetricKey = PSec.GenerateAsymmetricKeyPair();
                            var token = Securoman.GenerateToken(asymmetricKey, ticket.Principal.Claims, session.Id.ToString());
                            session.PublicKey = asymmetricKey.PublicKey.Key.ToArray();
                            session.PrivateKey = asymmetricKey.SecretKey.Key.ToArray();
                            
                            httpContext.Response.Cookies.Append("Identity.Token",
                                token, new CookieOptions
                                {
                                    Expires = DateTimeOffset.UtcNow.AddMinutes(5)
                                });
                            await authDbContext.SaveChangesAsync();
                        }
                        byte[] val = SerializeToBytes(ticket);
                        await _cache.SetAsync(key, val, options);
                    }
                    else if (_session.IsDeleted)
                    {
                        await RemoveAsync(key);
                    }
                    else
                    {
                        if (expiresUtc.HasValue)
                        {
                            _session.ExpirationDate = (expiresUtc.Value);
                        }
                        byte[] val = SerializeToBytes(ticket);
                        await _cache.SetAsync(key, val, options);
                        await authDbContext.SaveChangesAsync();
                    }
                }
            }else
            {
                throw new ApplicationException("AuthDbContext or HttpContextAccessor is null");
                byte[] val = SerializeToBytes(ticket);
                await _cache.SetAsync(key, val, options);
            }
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
