using System.Security.Claims;
using AuthService.Core;
using AuthService.Identity;
using CommonLibrary.AspNetCore.Identity;
using CommonLibrary.AspNetCore.Identity.Policies;
using CommonLibrary.AspNetCore.Logging;
using CommonLibrary.Identity.Models;
using MassTransit;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Controllers;

[Route("api/v{version:apiVersion}/[controller]")]
[ApiVersion("1.0")]
[ApiController]
[Authorize(Policy = UserPolicy.ELEVATED_RIGHTS)]
public class RoleController : ControllerBase
{
    private readonly UserDbContext _dbContext;
    private readonly UserSignInManager _userSignInManager;
    private readonly UserManager<User> _userManager;
    private readonly RoleManager<IdentityRole<Guid>> _roleManager;
    private readonly ILoggingService _loggingService;
    private IPublishEndpoint _publishEndpoint;

    public RoleController(
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
    [HttpGet("")]
    public async Task<IActionResult> GetRoles()
    {
        var roles = await _roleManager.Roles.ToListAsync();
        List<RoleIdentity> rolePrincipal = new();
        roles.ForEach( x=>  rolePrincipal.Add(new RoleIdentity
        {
            Name = x.Name,
            Properties =  _roleManager.GetClaimsAsync(x).Result.Select(y=> new RoleProperty{Type = y.Type, Value = y.Value}).ToList()
        }));
        return Ok(rolePrincipal);
    }

    [HttpPost("")]
    public async Task<IActionResult> CreateOrUpdateRole(RoleIdentity roleIdentity)
    {
        var existingRole = await _roleManager.FindByNameAsync(roleIdentity.Name);
        if (existingRole != null)
        {
            var existingRoleClaims = await _roleManager.GetClaimsAsync(existingRole);
            foreach (var existingRoleClaim in existingRoleClaims)
            {
                if (roleIdentity.Properties.All(x=> x.Value != existingRoleClaim.Value))
                    await _roleManager.RemoveClaimAsync(existingRole, existingRoleClaim);
            }
            foreach (var roleProperty in roleIdentity.Properties)
            {
                if (existingRoleClaims.Any(x => x.Value == roleProperty.Value))
                    continue;
                await _roleManager.AddClaimAsync(existingRole,
                    new Claim(roleProperty.Type, roleProperty.Value));
            }
        }
        else
        {
            var newRole = new IdentityRole<Guid>(roleIdentity.Name);
            await _roleManager.CreateAsync(newRole);
            foreach (var roleProperty in roleIdentity.Properties)
            {
                await _roleManager.AddClaimAsync(newRole, 
                    new Claim(roleProperty.Type,roleProperty.Value));
            }
        }
        _loggingService.Information($"User {User.FindFirst(UserClaimTypes.Id).Value} created or updated role: {roleIdentity.Name}", new Guid(User.FindFirst(UserClaimTypes.LogHandleId).Value));
        return Ok();
    }
    
    [HttpDelete("")]
    public async Task<IActionResult> DeleteRole(string roleName)
    {
        var role = await _roleManager.FindByNameAsync(roleName);
        if (role == null) return BadRequest();
        await _roleManager.DeleteAsync(role);
        _loggingService.Information($"User {User.FindFirst(UserClaimTypes.Id).Value} deleted role: {roleName}", new Guid(User.FindFirst(UserClaimTypes.LogHandleId).Value));
        return Ok();
    }


}