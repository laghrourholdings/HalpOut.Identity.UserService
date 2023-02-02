using AuthService.Core;
using AuthService.Identity;
using CommonLibrary.AspNetCore.Identity;
using CommonLibrary.AspNetCore.Logging;
using CommonLibrary.Identity;
using MassTransit;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Controllers;

[Route("api/v{version:apiVersion}/[controller]")]
[ApiVersion("1.0")]
[ApiController]
[Authorize]
public class TokenController : ControllerBase
{
    private readonly UserDbContext _dbContext;
    private readonly UserSignInManager _userSignInManager;
    private readonly UserManager<User> _userManager;
    private readonly RoleManager<IdentityRole<Guid>> _roleManager;
    private readonly ILoggingService _loggingService;
    private IPublishEndpoint _publishEndpoint;

    public TokenController(
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
    
    [HttpGet("invalidate/{userId:guid}")]
    public async Task<IActionResult> InvalidateUserWithId(Guid userId)
    {
        _publishEndpoint.Publish(new InvalidateUser(userId));
        return Ok();
    }


    [HttpGet("refreshBadge")]
    public async Task<IActionResult> RefreshBadge()
    {
        var token = Request.Cookies[SecuromanDefaults.TokenCookie];
        var unverifiedUserTicket = SecuromanTokenizer.GetUnverifiedUserClaims(token);
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
        var verificationResult = SecuromanTokenizer.VerifyToken(token, session.PublicKey);
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
    public async Task<IActionResult> RefreshToken()
    {
        try
        {
            var token = HttpContext.Request.Cookies[SecuromanDefaults.TokenCookie];
            var unsecurePayload = SecuromanTokenizer.GetUnverifiedUserClaims(token);
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

            var param = SecuromanTokenizer.DefaultParameters;
            param.ValidateLifetime = false;
            var verificationResult = SecuromanTokenizer.VerifyToken(
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
            var newToken = SecuromanTokenizer.GenerateToken(
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
            return Ok(newToken);
        }
        catch (Exception exception)
        {
            return BadRequest("Please re-authenticate");
        }
    }
    
    
    [HttpGet("invalidate")]
    public async Task<IActionResult> InvalidateUser()
    {
        var token = Request.Cookies[SecuromanDefaults.TokenCookie];
        var unverifiedUserTicket = SecuromanTokenizer.GetUnverifiedUserClaims(token);
        var ticketClaims = unverifiedUserTicket?.ToList();
        var userId = ticketClaims?.FirstOrDefault(x=>x.Type == UserClaimTypes.Id)?.Value;
        if(userId != null)
            _publishEndpoint.Publish(new InvalidateUser(new Guid(userId)));
        return Ok();
    }


}