using System.Security.Claims;
using AuthService.Identity.Managers;
using CommonLibrary.AspNetCore.Identity;
using CommonLibrary.AspNetCore.Identity.Model;
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
    private readonly AuthUserManager _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly ILogger _logger;

    public AuthController(IHttpContextAccessor context,
        UserSignInManager userSignInManager,
        AuthUserManager manager,
        RoleManager<IdentityRole> roleManager,
        Serilog.ILogger logger)
    {
        _context = context;
        _userSignInManager= userSignInManager;
        _userManager = manager;
        _roleManager = roleManager;
        _logger = logger;
    }
    
    [HttpPost("login")]
    public async Task<IActionResult> Login()
    {
        var result = await _userSignInManager.PasswordSignInAsync("username", "Password18!", false, false);
        if (_context.HttpContext.Request.Cookies.TryGetValue(".AspNetCore.Identity.Application", out var token))
        {
            Console.WriteLine(token);
        }
        if (result.Succeeded)
        {
            return Ok();
        }
        return BadRequest();
    }
    [AllowAnonymous]
    [HttpPost("register")]
    public async Task<IActionResult> Register()
    {
        var user = new User
        {
            UserName = "username",
            Email = "email@gmail.com",
            LogHandleId =  Guid.Empty,
            UserDetailsId  = Guid.Empty,
            UserDeviceId  = Guid.Empty,
            UserInterestId  = Guid.Empty,
            SessionId = Guid.Empty,
        };       
        var result = await _userManager.CreateAsync(user, "Password18!");
        var createdUser = await _userManager.FindByNameAsync(user.UserName);

        if (result.Succeeded)
        {
            var roleExist = await _roleManager.RoleExistsAsync("Administrator");
            if (!roleExist)
            { 
                await _roleManager.CreateAsync(new IdentityRole("Administrator"));
            }
            await _userManager.AddToRoleAsync(createdUser, "Administrator");
            await _userSignInManager.SignInAsync(createdUser,true);
            return Ok();
        }
        
        return BadRequest();
    }

    [HttpGet]
    [Authorize(Policy = Policies.ELEVATED_RIGHTS)]
    public async Task<IActionResult> Get()
    {
        return Ok("Nice!");
    }
    
}