using System.Security.Claims;
using AuthService.EFCore;
using AuthService.Identity.Managers;
using AuthService.Implementations;
using CommonLibrary.AspNetCore.Identity.Model;
using CommonLibrary.AspNetCore.Logging;
using MassTransit;
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
        byte[] val = SerializeToBytes(ticket);
        using (var scope = _services.BuildServiceProvider().CreateScope())
        {
            var authDbContext = scope.ServiceProvider.GetService<UserDbContext>();
            if (authDbContext != null)
            {
                var user = await authDbContext.Users.Include(x=>x.UserSessions).SingleOrDefaultAsync(x => x.Id == ticket.Principal.FindFirstValue(ClaimTypes.NameIdentifier));
                //var loggingService = scope.ServiceProvider.GetService<ILoggingService>();
                if (user != null)
                {
                    var session = authDbContext.UserSessions.Include(x=>x.Device).SingleOrDefault(x=>x.Key == key);
                    if (session == null)
                    {
                        var device = new UserDevice();
                        var httpContextAccessor = scope.ServiceProvider.GetService<IHttpContextAccessor>();
                        var httpContext = httpContextAccessor?.HttpContext;
                        var newSession = new UserSession
                        {
                            CreationDate = DateTimeOffset.Now,
                            ExpirationDate = ticket.Properties.ExpiresUtc,
                            Key = key,
                            RawAuthenticationTicket = SerializeToBytes(ticket),
                            Descriptor = "Issued by UserSessionStore",
                        };
                        if (httpContext != null)
                        {
                            var remoteIpAddress = httpContext.Connection.RemoteIpAddress;
                            device.CreationDate = DateTimeOffset.Now;

                            if (remoteIpAddress != null)
                            {
                                device.IpAddress = remoteIpAddress.ToString();
                            }
                            var userAgent = httpContext.Request.Headers["User-Agent"];
                            device.UserAgent = userAgent;
                            if (!string.IsNullOrEmpty(userAgent))
                            {
                                var uaParser = UAParser.Parser.GetDefault();
                                var clientInfo = uaParser.Parse(userAgent);
                                device.DeviceOs = clientInfo.OS.ToString();
                                device.DeviceType = clientInfo.UserAgent.Family;
                                device.DeviceName = clientInfo.Device.Model;
                                device.DeviceModel =
                                    $"{clientInfo.UserAgent.Major}.{clientInfo.UserAgent.Minor}.{clientInfo.UserAgent.Patch}";
                            }

                            newSession.Device = device;
                        }

                        user.UserSessions.Add(newSession);
                        await authDbContext.SaveChangesAsync();
                        //loggingService.InformationToBusLog($"New session issued {newSession.Id}", user.LogHandleId);
                    }
                    else if (session.IsDeleted)
                    {
                        await RemoveAsync(key);
                        //loggingService.InformationToBusLog($"Processing session deletion, removing from cache... {session.Id}", user.LogHandleId);
                        return;
                    }
                    else
                    {
                        if (expiresUtc.HasValue)
                        {
                            session.ExpirationDate = (expiresUtc.Value);
                        }
                        session.RawAuthenticationTicket = val;
                        //loggingService.InformationToBusLog( $"Patching session {session.Id}", user.LogHandleId);
                        await authDbContext.SaveChangesAsync();
                    }
                    await _cache.SetAsync(key, val, options);
                }
            }else
            {
                //logger?.ErrorToBusLog(config, $"CRITICAL: DATABASE UNREACHEABLE AT USERSESSIONSTORE", user.LogHandleId, publishEnpoint);
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
                    var userSession = await context.UserSessions.SingleOrDefaultAsync(x => x.Key == key);
                    if (userSession != null)
                    {
                        if(userSession.IsDeleted)
                        {
                            await RemoveAsync(key);
                            context.UserSessions.Remove(userSession);
                            await context.SaveChangesAsync();
                            return null;
                        }
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
