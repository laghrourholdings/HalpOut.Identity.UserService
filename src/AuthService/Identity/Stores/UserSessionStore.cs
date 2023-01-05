using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthService.EFCore;
using CommonLibrary.AspNetCore.Identity.Models;
using CommonLibrary.Utilities;
using Flurl.Util;
using JWT;
using JWT.Algorithms;
using JWT.Builder;
using JWT.Exceptions;
using JWT.Serializers;
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
            if (authDbContext != null)
            {
                var user = await authDbContext.Users.Include(x=>x.UserSessions).SingleOrDefaultAsync(x => x.Id == ticket.Principal.FindFirstValue(ClaimTypes.NameIdentifier));
                if (user != null)
                {
                    var httpContextAccessor = scope.ServiceProvider.GetService<IHttpContextAccessor>();
                    var httpContext = httpContextAccessor?.HttpContext;
                    var _session = authDbContext.UserSessions.Include(x=>x.Device).SingleOrDefault(x=>x.CacheKey == key);
                    if (_session == null)
                    {
                        var newSession = new UserSession
                        {
                            CreationDate = DateTimeOffset.Now,
                            ExpirationDate = ticket.Properties.ExpiresUtc,
                            CacheKey = key
                        };
                        if (httpContext != null)
                        {
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
                                    var device = new UserDevice();
                                    var uaParser = UAParser.Parser.GetDefault();
                                    Console.WriteLine(uaParser.ToString());
                                    var clientInfo = uaParser.Parse(userAgent);
                                    device.CreationDate = DateTimeOffset.Now;
                                    if (remoteIpAddress != null)
                                    {
                                        device.IpAddress = remoteIpAddress.ToString();
                                    }
   
                                    device.UserAgent = userAgent;
                                    device.DeviceOs = clientInfo.OS.ToString();
                                    device.DeviceType = clientInfo.UserAgent.Family;
                                    device.DeviceName = clientInfo.Device.Model;
                                    device.DeviceModel =
                                        $"{clientInfo.UserAgent.Major}.{clientInfo.UserAgent.Minor}.{clientInfo.UserAgent.Patch}";
                                    device.Hash = deviceHash;
                                    newSession.Device = device;
                                }
                            }
                        }
                        user.UserSessions.Add(newSession);
                        await authDbContext.SaveChangesAsync();
                        var session = authDbContext.UserSessions.Include(x=>x.Device).SingleOrDefault(x=>x.CacheKey == key);
                        if (session != null)
                        {
                            
                            var rsa = RSA.Create();
                            Console.WriteLine(ASCIIEncoding.UTF8.GetString(rsa.ExportRSAPrivateKey()));
                            Console.WriteLine("PUBLIC:");
                            Console.WriteLine(ASCIIEncoding.UTF8.GetString(rsa.ExportRSAPublicKey()));
                            Console.WriteLine("PUBLIC:");
                            var token = JwtBuilder.Create()
                                .WithAlgorithm(new RS256Algorithm(rsa,rsa))
                                .AddClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
                                .AddClaim("Session",session.Id.ToString())
                                .AddClaims(ticket.Principal.Claims.Select(x=>new KeyValuePair<string, object>(x.Type, x.Value)))
                                .WithSecret("secret")
                                .Encode();
                            httpContext.Response.Cookies.Append("Identity.Token",
                                token, new CookieOptions
                                {
                                    Expires = DateTimeOffset.UtcNow.AddHours(1),
                                    HttpOnly = true
                                });
                            session.Token = token;
                            session.PrivateKey = rsa.ExportRSAPrivateKey();
                            session.PublicKey = rsa.ExportRSAPublicKey();
                            
                            var rsa2 = RSA.Create();
                            //rsa2.ImportRSAPrivateKey(rsa.ExportRSAPrivateKey(), out _);
                            //rsa2.ImportRSAPublicKey(rsa.ExportRSAPublicKey(), out _);
                            try
                            {
                                IJsonSerializer serializer = new JsonNetSerializer();
                                IDateTimeProvider provider = new UtcDateTimeProvider();
                                IJwtValidator validator = new JwtValidator(serializer, provider);
                                IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
                                IJwtAlgorithm algorithm = new RS256Algorithm(rsa2);
                                IJwtDecoder decoder = new JwtDecoder(serializer, validator, urlEncoder, algorithm);
    
                                var json = decoder.Decode(token);
                                Console.WriteLine(json);
                            }
                            catch (TokenNotYetValidException)
                            {
                                Console.WriteLine("Token is not valid yet");
                            }
                            catch (TokenExpiredException)
                            {
                                Console.WriteLine("Token has expired");
                            }
                            catch (SignatureVerificationException)
                            {
                                Console.WriteLine("Token has invalid signature");
                            }
                            
                            
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
