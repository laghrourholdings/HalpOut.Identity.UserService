using System.Security.Claims;
using System.Text.Json;
using AuthService.Core;
using AuthService.Identity;
using CommonLibrary.AspNetCore.Identity;
using CommonLibrary.AspNetCore.Identity.Policies;
using CommonLibrary.AspNetCore.Logging;
using CommonLibrary.Identity;
using CommonLibrary.Identity.Dtos;
using MassTransit;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Controllers;

[Route("api/v{version:apiVersion}/[controller]")]
[ApiVersion("1.0")]
[ApiController]
public class UserController : ControllerBase
{
    private readonly UserDbContext _dbContext;
    private readonly UserSignInManager _userSignInManager;
    private readonly UserManager<User> _userManager;
    private readonly RoleManager<IdentityRole<Guid>> _roleManager;
    private readonly ILoggingService _loggingService;
    private IPublishEndpoint _publishEndpoint;

    public UserController(
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
                _loggingService.Information(
                    $"User logged in with device: {HttpContext.Request.Headers.UserAgent}", user.LogHandleId);
                return Ok();
            }
        }
        _loggingService.Information($"Logging failed for {userCredentialsDto.Username}");
        return BadRequest();
    }
    
    [HttpGet("signout")]
    [Authorize(Policy = UserPolicy.AUTHENTICATED)]
    public async Task<IActionResult> SignUserOut()
    {
        var userId = HttpContext.User.Claims.FirstOrDefault(x=>x.Type == UserClaimTypes.Id)?.Value;
        if(userId != null)
            _publishEndpoint.Publish(new InvalidateUser(new Guid(userId)));
        await _userSignInManager.SignOutAsync();
        Response.Cookies.Delete(SecuromanDefaults.TokenCookie);
        return Ok();
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
                new Claim(UserClaimTypes.Right, "projects.create"));
            await _roleManager.AddClaimAsync(adminRole, 
                new Claim(UserClaimTypes.Right, "projects.read"));
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
        return Ok();
    }
    
    [HttpPost("role")]
    [Authorize(Policy = UserPolicy.ELEVATED_RIGHTS)]
    public async Task<IActionResult> AddUserToRole([FromBody] UserRoleDto arg)
    {
        var user =  _userManager.Users.SingleOrDefault(x => x.Id == arg.UserId);
        if(user == null) 
            return BadRequest();
        var userRoles = await _userManager.GetRolesAsync(user);
        if (userRoles.Contains(arg.RoleName)) return Ok();
        var role = await _roleManager.FindByNameAsync(arg.RoleName);
        if (role == null) 
            return BadRequest();
        await _userManager.AddToRoleAsync(user, role.Name);
        _loggingService.Information($"User now in {arg.RoleName}", user.LogHandleId);
        _loggingService.Information($"Added user {user.Id} to role: {arg.RoleName}",new Guid(User.FindFirst(UserClaimTypes.LogHandleId).Value));
        _publishEndpoint.Publish(new InvalidateUser(arg.UserId));
        await _userSignInManager.RefreshSignInAsync(user);
        return Ok();
    }
    
    [HttpDelete("role")]
    [Authorize(Policy = UserPolicy.ELEVATED_RIGHTS)]
    public async Task<IActionResult> RemoveUserFromRole(UserRoleDto arg)
    {
        var user =  _userManager.Users.SingleOrDefault(x => x.Id == arg.UserId);
        if(user == null) 
            return BadRequest();
        var userRoles = await _userManager.GetRolesAsync(user);
        if (userRoles.Contains(arg.RoleName))
        { 
            await _userManager.RemoveFromRoleAsync(user, arg.RoleName);
            _loggingService.Information($"User removed from role {arg.RoleName}", user.LogHandleId);
            _loggingService.Information($"Removed user {user.Id} from role: {arg.RoleName}", new Guid(User.FindFirst(UserClaimTypes.LogHandleId).Value));
            await _userSignInManager.RefreshSignInAsync(user);
            _publishEndpoint.Publish(new InvalidateUser(arg.UserId));
        }
        return Ok();
    }
    
    [HttpGet("{userId:guid}/roles")]
    [Authorize(Policy = UserPolicy.ELEVATED_RIGHTS)]
    public async Task<IActionResult> GetRoles(Guid userId)
    {
        var roles = (await _userManager.GetRolesAsync(new User{Id = userId})).ToList();
        List<RoleIdentity> rolePrincipal = new();
        roles.ForEach( x=>  rolePrincipal.Add(new RoleIdentity
        {
            Name = x,
            Properties =  _roleManager
                .GetClaimsAsync(_roleManager.FindByNameAsync(x).Result)
                .Result.Select(y=> new RoleProperty{Type = y.Type, Value = y.Value}).ToList()
        }));
        return Ok(rolePrincipal);
    }
    
    
}