using System.Security.Claims;
using System.Text;
using System.Text.Json;
using AuthService.Core;
using AuthService.Identity;
using CommonLibrary.AspNetCore.Identity;
using CommonLibrary.AspNetCore.Identity.Policies;
using CommonLibrary.AspNetCore.Logging;
using CommonLibrary.Identity.Models;
using CommonLibrary.Identity.Models.Dtos;
using MassTransit;
using MassTransit.Initializers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Deviceman = AuthService.Identity.Deviceman;
using Securoman = CommonLibrary.AspNetCore.Identity.Securoman;

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
                // var token = GetResponseCookieData()[SecuromanDefaults.TokenCookie];
                // var verificationResult = Securoman.VerifyTokenWithSecret(token, user.SecretKey);
                _loggingService.Information(
                    $"User logged in with device: {HttpContext.Request.Headers.UserAgent}", user.LogHandleId);
                return Ok(/*new { PK = Encoding.UTF8.GetString(verificationResult.PublicKey) }*/);
            }
        }
        _loggingService.Information($"Logging failed for {userCredentialsDto.Username}");
        return BadRequest();
    }



    [HttpGet("invalidate")]
    public async Task<IActionResult> InvalidateUser()
    {
        var token = Request.Cookies[SecuromanDefaults.TokenCookie];
        var unverifiedUserTicket = Securoman.GetUnverifiedUserTicket(token);
        var ticketClaims = unverifiedUserTicket?.ToList();
        var userId = ticketClaims?.FirstOrDefault(x=>x.Type == UserClaimTypes.Id)?.Value;
        if(userId != null)
            _publishEndpoint.Publish(new InvalidateUser(new Guid(userId)));
        return Ok();
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
    
    [HttpGet("invalidate/{userId:guid}")]
    public async Task<IActionResult> InvalidateUserWithId(Guid userId)
    {
        _publishEndpoint.Publish(new InvalidateUser(userId));
        return Ok();
    }


    [HttpGet("refreshBadge")]
    [Authorize(Policy = UserPolicy.AUTHENTICATED)]
    public async Task<IActionResult> RefreshBadge()
    {
        var token = Request.Cookies[SecuromanDefaults.TokenCookie];
        var unverifiedUserTicket = Securoman.GetUnverifiedUserTicket(token);
        var ticketClaims = unverifiedUserTicket?.ToList();
        var userId = ticketClaims?.FirstOrDefault(x=>x.Type == UserClaimTypes.Id)?.Value;
        var sessionId = ticketClaims?.FirstOrDefault(x => x.Type == UserClaimTypes.SessionId)?.Value;
        if (userId == null || sessionId == null) return NotFound();
        var user = _dbContext.Users.Include(x=>x.UserSessions).FirstOrDefault(x=>x.Id == new Guid(userId));
        //device not included in LINQ request
        if(user == null)
            return NotFound();
        var session = user.UserSessions.FirstOrDefault(s => s.Id == new Guid(sessionId));
        if (session == null || session.IsDeleted) 
            return NotFound();
        var verificationResult = Securoman.VerifyToken(token, session.PublicKey);
        if (verificationResult.Result.IsValid)
        {
            /*var userRoles = await _userManager.GetRolesAsync(user);
            var rolePrincipal = new List<RoleIdentity>();
            foreach (var userRole in userRoles)
            {
                var roleIdentity = new RoleIdentity();
                var role = await _roleManager.FindByNameAsync(userRole);
                if (role == null) continue;
                roleIdentity.Name = userRole;
                var roleClaims = await _roleManager.GetClaimsAsync(role);
                foreach (var roleClaim in roleClaims)
                {
                    roleIdentity.Properties.Add(
                        new RoleProperty
                        {
                            Type = roleClaim.Type,
                            Value = roleClaim.Value
                        });
                }
                rolePrincipal.Add(roleIdentity);
            }*/
            var userBadge = new UserBadge()
            {
                LogHandleId = user.LogHandleId,
                UserId = user.Id,
                SecretKey = user.SecretKey,
                //RolePrincipal = rolePrincipal
            };
            return Ok(userBadge);
        }
        return NotFound();
    }
    
    [HttpGet("refreshToken")]
    [Authorize(Policy = UserPolicy.AUTHENTICATED)]
    public async Task<IActionResult> RefreshToken()
    {
        try
        {
            var token = HttpContext.Request.Cookies[SecuromanDefaults.TokenCookie];
            var unsecurePayload = Securoman.GetUnverifiedUserTicket(token);
            if (unsecurePayload is null)
                return BadRequest("Please re-authenticate");
            var userId = HttpContext.User.Claims.First(x => x.Type == UserClaimTypes.Id).Value;
            // Get authenticated user
            var sessionUser = _dbContext.Users
                .Include(x => x.UserSessions)
                .ThenInclude(x => x.Device).SingleOrDefault(x => x.Id == new Guid(userId));
            if (sessionUser == null)
                return BadRequest("Please re-authenticate");

            var tokenSessionId = new Guid(unsecurePayload.First(x => x.Type == UserClaimTypes.SessionId).Value);
            var session = sessionUser.UserSessions.FirstOrDefault(s =>
                s.Id == tokenSessionId);

            if (session is null)
                return BadRequest("Please re-authenticate");

            var param = Securoman.DefaultParameters;
            param.ValidateLifetime = false;
            var verificationResult = Securoman.VerifyToken(
                token,
                session.PublicKey, param);

            if (!verificationResult.Result.IsValid || verificationResult.HasInvalidSecretKey)
            {
                return BadRequest("Please re-authenticate");
            }

            var callerDevice = Deviceman.CreateDevice(
                HttpContext.Request.Headers["User-Agent"],
                HttpContext.Connection.RemoteIpAddress.ToString(),
                new Guid(userId));
            if (session.IsDeleted || session.Device.Hash != callerDevice.Hash)
            {
                await _userSignInManager.SignOutAsync();
                Response.Cookies.Delete(SecuromanDefaults.TokenCookie);
                return BadRequest("Please re-authenticate");
            }

            var exp = DateTimeOffset.UtcNow.AddMinutes(5);
            var asymmetricKey = Pasetoman.AsymmetricKeyPair(session.PrivateKey, session.PublicKey);
            var newToken = Securoman.GenerateToken(
                asymmetricKey,
                HttpContext.User.Claims,
                sessionUser.SecretKey,
                session.Id,
                exp);
            HttpContext.Response.Cookies.Append(SecuromanDefaults.TokenCookie,
                newToken, new CookieOptions
                {
                    Expires = new DateTimeOffset(2038, 1, 1, 0, 0, 0, TimeSpan.FromHours(0)),
                    Secure = true
                });
            return Ok();
        }
        catch (Exception exception)
        {
            return BadRequest("Please re-authenticate");
        }
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
        //await _userSignInManager.SignInAsync(user,true);
        return Ok();
    }
    
    [HttpPost("role")]
    [Authorize(Policy = UserPolicy.ELEVATED_RIGHTS)]
    public async Task<IActionResult> AddUserToRole([FromBody] UserRoleDto arg)
    {
        //var user = await _userManager.FindByIdAsync(arg.UserId.ToString());
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
        //var user = await _userManager.FindByIdAsync(arg.UserId.ToString());
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