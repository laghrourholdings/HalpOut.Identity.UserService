using System.Security.Claims;
using System.Text.Json;
using AuthService.Identity.Managers;
using CommonLibrary.AspNetCore.Contracts.Users;
using CommonLibrary.AspNetCore.Identity;
using CommonLibrary.AspNetCore.Identity.Model;
using CommonLibrary.AspNetCore.Logging;
using CommonLibrary.AspNetCore.Logging.LoggingService;
using MassTransit;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using ILogger = Serilog.ILogger;

namespace AuthService.Controllers.Auth;

[Route("api/v{version:apiVersion}/[controller]")]
[ApiVersion("1.0")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly IHttpContextAccessor _context;
    public readonly UserSignInManager _userSignInManager;
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
    
    [HttpPost("login")]
    public async Task<IActionResult> Login(
        string username, 
        string password)
    {
        var result = await _userSignInManager.PasswordSignInAsync(username, password, false, false);
        if (result.Succeeded)
        {
            var user = await _userManager.FindByNameAsync(username);
            _loggingService.InformationToLogService($"User logged in with device: {_context.HttpContext.Request.Headers.UserAgent}",user.LogHandleId);
            if (_context.HttpContext != null && _context.HttpContext.Request.Cookies.TryGetValue(".AspNetCore.Identity.Application", out var token))
            {
                Console.WriteLine(token);
                await _userManager.AddLoginAsync(user, new UserLoginInfo("AuthService", token, user.Id));
            }
            return Ok();
        }
        _loggingService.Log().Information("Logging failed for {username}, with device: {UserAgent}",username, _context.HttpContext.Request.Headers.UserAgent);
        return BadRequest();
    }
    [AllowAnonymous]
    [HttpPost("register")]
    public async Task<IActionResult> Register(
        string username, 
        string email,
        string password)
    {
        var user = new User
        {
            UserName = username,
            Email = email,
            LogHandleId =  Guid.Empty
        };       
        var result = await _userManager.CreateAsync(user, password);
        if (result.Succeeded)
        {
            var createdUser = await _userManager.FindByNameAsync(user.UserName);
            await _publishEndpoint.Publish(new UserCreated(new Guid(createdUser.Id)));
            var roleExist = await _roleManager.RoleExistsAsync("Administrator");
            if (!roleExist)
            { 
                await _roleManager.CreateAsync(new IdentityRole("Administrator"));
            }
            await _userManager.AddToRoleAsync(createdUser, "Administrator");
            await _userSignInManager.SignInAsync(createdUser,true);
            return Ok();
        }
        
        return BadRequest($"User creation failed {JsonSerializer.Serialize(result.Errors)}");
    }

    [HttpGet]
    [Authorize(Policy = Policies.ELEVATED_RIGHTS)]
    public async Task<IActionResult> Get()
    {
        if (_context.HttpContext != null && _context.HttpContext.Request.Cookies.TryGetValue(".AspNetCore.Identity.Application", out var token))
        {
            Console.WriteLine(token);
            //await _userManager.
        }
        User? user = _userManager.FindByNameAsync(_context.HttpContext?.User.Identity?.Name ?? string.Empty).Result;
        //_userManager.AddLoginAsync(user, new UserLoginInfo("AuthService"));
        _loggingService.Log().Information("User logged with privileges: {user}", user);
        return Ok("Authorzied!");
    }
    
}