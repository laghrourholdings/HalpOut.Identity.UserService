using System.Security.Claims;
using System.Text;
using System.Text.Json;
using AuthService.EFCore;
using AuthService.Identity.Managers;
using CommonLibrary.AspNetCore.Identity;
using CommonLibrary.AspNetCore.Identity.Helpers;
using CommonLibrary.AspNetCore.Identity.Models;
using CommonLibrary.AspNetCore.Logging.LoggingService;
using CommonLibrary.AspNetCore.ServiceBus.Contracts.Logging;
using CommonLibrary.AspNetCore.ServiceBus.Contracts.Users;
using CommonLibrary.Identity.Models.Dtos;
using MassTransit;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Paseto;

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
        foreach (var parts in Request.Headers.SetCookie.ToArray().Select(c => c.Split(new[] { '=' }, 2)))
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
        if(HttpContext.User.Identity != null && HttpContext.User.Identity.IsAuthenticated)
            return BadRequest("User is already authenticated");
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
    
    [HttpPost("refresh")]
    [Authorize(Policy = Policies.AUTHENTICATED)]
    public async Task<IActionResult> Refresh()
    {
        // Get authenticated user
        var user = _userManager.GetUserAsync(HttpContext.User);
        var sessionId = HttpContext.User.Claims.FirstOrDefault(x => x.Type == UserClaimTypes.UserSessionId)?.Value;
        if (sessionId != null)
        {
            //Debug why DB Context not working
            var sessionGuid = Guid.Parse(sessionId);
            var session = _dbContext.UserSessions.FirstOrDefault(s => s.Id == sessionGuid);
            Console.WriteLine("");
        }
        
        Console.WriteLine("");
        return BadRequest();
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
            SecretKey = PSec.GenerateSymmetricKey().Key.ToArray()
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
                new Claim(UserClaimTypes.Previlege, "projects.create", ClaimValueTypes.String, "AuthService"));
            await _roleManager.AddClaimAsync(adminRole, 
                new Claim(UserClaimTypes.Previlege, "projects.read", ClaimValueTypes.String, "AuthService"));
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