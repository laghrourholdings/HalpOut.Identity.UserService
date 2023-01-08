using System.Security.Claims;
using System.Text;
using System.Text.Json;
using AuthService.Identity.Managers;
using CommonLibrary.AspNetCore.Identity;
using CommonLibrary.AspNetCore.Identity.Helpers;
using CommonLibrary.AspNetCore.Identity.Models;
using CommonLibrary.AspNetCore.Logging.LoggingService;
using CommonLibrary.AspNetCore.ServiceBus.Contracts.Users;
using CommonLibrary.Identity.Models.Dtos;
using MassTransit;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Controllers.Permissions;

[Route("api/v{version:apiVersion}/[controller]")]
[ApiVersion("1.0")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly IHttpContextAccessor _context;
    private readonly UserSignInManager _userSignInManager;
    private readonly UserManager<User> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly ILoggingService _loggingService;
    private IPublishEndpoint _publishEndpoint;

    public AuthController(IHttpContextAccessor context,
        UserSignInManager userSignInManager,
        UserManager<User> manager,
        RoleManager<IdentityRole> roleManager,
        ILoggingService loggingService, 
        IPublishEndpoint publishEndpoint)
    {
        _context = context;
        _userSignInManager= userSignInManager;
        _userManager = manager;
        _roleManager = roleManager;
        _loggingService = loggingService;
        _publishEndpoint = publishEndpoint;
    }
    
    private IDictionary<string, string> GetCookieData()
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
    
    //TODO add loghandleId to claims trust
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] UserCredentialsDto userCredentialsDto)
    {
        var result = await _userSignInManager.PasswordSignInAsync(userCredentialsDto.Username, userCredentialsDto.Password, false, false);
        var token = GetCookieData()["Identity.Token"]; 
        if (result.Succeeded)
        {
            //To fix: 
            var verificationResult = Securoman.VerifyToken(token);
            _loggingService.Local().Information("{@verificationResult}", verificationResult);
            var user = await _userManager.FindByNameAsync(userCredentialsDto.Username);
            if(user.LogHandleId == Guid.Empty)
                await _publishEndpoint.Publish(new UserCreated(new Guid(user.Id)));
            _loggingService.Information($"User logged in with device: {_context.HttpContext.Request.Headers.UserAgent}",user.LogHandleId);
            return Ok(Encoding.UTF8.GetString(verificationResult.PublicKey));
        }
        _loggingService.Information($"Logging failed for {userCredentialsDto.Username}");
        return BadRequest();
    }
    [AllowAnonymous]
    [HttpPost("register")]
    public async Task<IActionResult> Register(
        string username, 
        string email,
        string password)
    {
        var generatedId = Guid.NewGuid().ToString();
        var user = new User
        {
            Id = generatedId,
            UserName = username,
            Email = email,
            LogHandleId =  Guid.Empty
        };       
        var result = await _userManager.CreateAsync(user, password);
        if (!result.Succeeded) return BadRequest($"User creation failed {JsonSerializer.Serialize(result.Errors)}");
        
        await _publishEndpoint.Publish(new UserCreated(new Guid(generatedId)));
        
        //Temporary
        var adminRole = await _roleManager.FindByNameAsync("Admin");
        if (adminRole == null)
        { 
            adminRole = new IdentityRole("Admin");
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
        await _userSignInManager.SignInAsync(user,true);
        return Ok();
    }

    [HttpGet("refresh")]
    [Authorize(Policy = Policies.AUTHENTICATED)]
    public async Task<IActionResult> Get()
    {
        await _userManager.FindByIdAsync(_context.HttpContext.User.Claims.First(x => x.Type == ClaimTypes.NameIdentifier).Value);
        
        return Ok($"Authorzied: {await _userManager.GetUserAsync(HttpContext.User)}");
    }
    
}