using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using AuthService.Core;
using AuthService.Identity;
using CommonLibrary.AspNetCore.Identity;
using CommonLibrary.AspNetCore.Logging;
using CommonLibrary.Identity.Models;
using CommonLibrary.Identity.Models.Dtos;
using MassTransit;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Paseto;
using Deviceman = AuthService.Identity.Deviceman;
using Securoman = CommonLibrary.AspNetCore.Identity.Securoman;

namespace AuthService.Controllers.Permissions;

[Route("api/v{version:apiVersion}/[controller]")]
[ApiVersion("1.0")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly UserDbContext _dbContext;
    private readonly UserSignInManager _userSignInManager;
    private readonly UserManager<User> _userManager;
    private readonly RoleManager<IdentityRole<Guid>> _roleManager;
    private readonly ILoggingService _loggingService;
    private IPublishEndpoint _publishEndpoint;

    public AuthController(
        UserDbContext dbContext,
        UserSignInManager userSignInManager,
        UserManager<User> manager,
        RoleManager<IdentityRole<Guid>> roleManager,
        ILoggingService loggingService, 
        IPublishEndpoint publishEndpoint)
    {
        _dbContext = dbContext;
        _userSignInManager= userSignInManager;
        _userManager = manager;
        _roleManager = roleManager;
        _loggingService = loggingService;
        _publishEndpoint = publishEndpoint;
    }
    
    private IDictionary<string, string> GetResponseCookieData()
    {
        var cookieDictionary = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var parts in Response.Headers.SetCookie.ToArray().Select(c => c.Split(new[] { '=' }, 2)))
        {
            var cookieName = parts[0].Trim();
            string cookieValue;

            if (parts.Length == 1)
            {
                //Cookie attribute
                cookieValue = string.Empty;
            }
            else
            {
                cookieValue = parts[1].Remove(parts[1].IndexOf(';'));
            }

            cookieDictionary[cookieName] = cookieValue;
        }

        return cookieDictionary;
    }
    
    private IDictionary<string, string> GetRequestCookieData()
    {
        var cookieDictionary = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var parts in HttpContext.Request.Headers.Cookie.ToArray().Select(c => c.Split(new[] { '=' }, 2)))
        {
            var cookieName = parts[0].Trim();
            string cookieValue;

            if (parts.Length == 1)
            {
                //Cookie attribute
                cookieValue = string.Empty;
            }
            else
            {
                cookieValue = parts[1].Remove(parts[1].IndexOf(';'));
            }

            cookieDictionary[cookieName] = cookieValue;
        }

        return cookieDictionary;
    }
    
    //TODO add loghandleId to claims trust
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] UserCredentialsDto userCredentialsDto)
    {
        if (HttpContext.User.Identity != null && HttpContext.User.Identity.IsAuthenticated)
            await _userSignInManager.SignOutAsync();
        var user = await _userManager.FindByNameAsync(userCredentialsDto.Username);
        if (user is not null)
        {
            var result = await _userSignInManager.CheckPasswordSignInAsync(user,userCredentialsDto.Password, false);
            if (result.Succeeded)
            {
                await _userSignInManager.SignInAsync(user, true);
                var token = GetResponseCookieData()["Identity.Token"];
                var verificationResult = Securoman.VerifyTokenWithSecret(token, user.SecretKey);
                _loggingService.Information(
                    $"User logged in with device: {HttpContext.Request.Headers.UserAgent}", user.LogHandleId);
                return Ok(new { PK = Encoding.UTF8.GetString(verificationResult.PublicKey) });
            }
        }
        _loggingService.Information($"Logging failed for {userCredentialsDto.Username}");
        return BadRequest();
    }

    [HttpGet("refreshBadge")]
    public async Task<IActionResult> RefreshBadge(string token)
    {
        //var userr = HttpContext.User;
        var unverifiedUserTicket = Securoman.GetUnverifiedUserTicket(token);
        var ticketClaims = unverifiedUserTicket?.ToList();
        var userId = ticketClaims?.FirstOrDefault(x=>x.Type == ClaimTypes.NameIdentifier)?.Value;
        var sessionId = ticketClaims?.FirstOrDefault(x => x.Type == UserClaimTypes.UserSessionId)?.Value;
        if (userId == null || sessionId == null) return NotFound();
        var user = _userManager.Users.FirstOrDefault(x=>x.Id == new Guid(userId));
        
        //device not included in LINQ request
        var session = _dbContext.UserSessions.FirstOrDefault(s => s.Id == new Guid(sessionId));
        if (user == null || session == null || session.IsDeleted) return NotFound();
        
        var verificationResult = Securoman.VerifyToken(token, session.PublicKey);
        if (verificationResult.Result.IsValid)
        {
            return Ok(new UserBadge()
            {
                UserId = new Guid(userId),
                LogHandleId = user.LogHandleId,
                SecretKey = user.SecretKey,
            });
        }
        return NotFound();
    }
    
    [HttpGet("refreshToken")]
    [Authorize(Policy = Policies.AUTHENTICATED)]
    public async Task<IActionResult> RefreshToken()
    {
        // Get authenticated user
        var sessionUser = await _userManager.GetUserAsync(HttpContext.User);
        if (sessionUser == null
            || !HttpContext.User.HasClaim(x => x.Type == ClaimTypes.NameIdentifier)
            || !HttpContext.User.HasClaim(x => x.Type == UserClaimTypes.UserSessionId))
            return BadRequest("User is not authenticated");

        var sessionId = new Guid(HttpContext.User.Claims.FirstOrDefault(x => x.Type == UserClaimTypes.UserSessionId)!
            .Value);
        var session = _dbContext.UserSessions.Include(x=>x.Device)
            .FirstOrDefault(s => 
                s.Id == sessionId);
        
        var token = HttpContext.Request.Cookies["Identity.Token"];
        
        if (token is null || session is null)
            return BadRequest("Token or session is null");

        var param = Securoman.DefaultParameters;
        param.ValidateLifetime = false;
        var verificationResult = Securoman.VerifyToken(
            token,
            session.PublicKey, param);
        if (!verificationResult.Result.IsValid)
        {
            //await _userSignInManager.SignOutAsync();
            return BadRequest("Token is invalid");
        }

        var tokenUserId = verificationResult.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)!.Value;
        var tokenSessionId = verificationResult.Claims.FirstOrDefault(x => x.Type == UserClaimTypes.UserSessionId)!.Value;
        
        var callerDevice = Deviceman.CreateDevice(
            HttpContext.Request.Headers["User-Agent"],
            HttpContext.Connection.RemoteIpAddress.ToString(),
            new Guid(tokenUserId));
        if (session.IsDeleted
            || session.Id.ToString() != tokenSessionId
            || tokenUserId != session.UserId.ToString()
            || session.Device.Hash != callerDevice.Hash)
        {
            await _userSignInManager.SignOutAsync();
            return BadRequest("Please re-authenticate");
        }
        
        var exp = DateTimeOffset.UtcNow.AddMinutes(5);
        var asymmetricKey = Pasetoman.AsymmetricKeyPair(session.PrivateKey, session.PublicKey);
        var newToken = Securoman.GenerateToken(
            asymmetricKey,
            HttpContext.User.Claims,
            sessionUser.SecretKey, exp);
        HttpContext.Response.Cookies.Append("Identity.Token",
            newToken, new CookieOptions
            {
                Expires = new DateTimeOffset(2038, 1, 1, 0, 0, 0, TimeSpan.FromHours(0))
            });
        return Ok(newToken);
    }
    
    [AllowAnonymous]
    [HttpPost("register")]
    public async Task<IActionResult> Register(
        string username, 
        string email,
        string password)
    {
        var logHandleId = Guid.NewGuid();
        var user = new User
        {
            UserName = username,
            Email = email,
            UserType = "Member",
            LogHandleId =  logHandleId,
            SecretKey = Pasetoman.GenerateSymmetricKey().Key.ToArray()
        };       
        var result = await _userManager.CreateAsync(user, password);
        if (!result.Succeeded) 
            return BadRequest($"User creation failed {JsonSerializer.Serialize(result.Errors)}");

        //Temporary
        var adminRole = await _roleManager.FindByNameAsync("Admin");
        if (adminRole == null)
        { 
            adminRole = new IdentityRole<Guid>("Admin");
            await _roleManager.CreateAsync(adminRole);
            await _roleManager.AddClaimAsync(adminRole, 
                new Claim(UserClaimTypes.Previlege, "projects.create", ClaimValueTypes.String, "UserService"));
            await _roleManager.AddClaimAsync(adminRole, 
                new Claim(UserClaimTypes.Previlege, "projects.read", ClaimValueTypes.String, "UserService"));
        }
        if (!await _userManager.IsInRoleAsync(user, adminRole.Name))
        {
            var r = await _userManager.AddToRoleAsync(user, adminRole.Name);
            if (!r.Succeeded)
            { 
                _loggingService.Error($"Can't assign user to role {adminRole.Name}, error: {JsonSerializer.Serialize(r.Errors)}",
                    user.LogHandleId);
            }
        }
        //await _userSignInManager.SignInAsync(user,true);
        return Ok();
    }
    
    
}