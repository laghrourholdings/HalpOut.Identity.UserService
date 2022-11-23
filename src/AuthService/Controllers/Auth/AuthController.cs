﻿using System.Security.Claims;
using AuthService.Identity.Managers;
using CommonLibrary.AspNetCore.Identity;
using CommonLibrary.AspNetCore.Identity.Model;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

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

    public AuthController(IHttpContextAccessor context,
        UserSignInManager userSignInManager,
        UserManager<User> manager,
        RoleManager<IdentityRole> roleManager)
    {
        _context = context;
        _userSignInManager= userSignInManager;
        _userManager = manager;
        _roleManager = roleManager;
    }
    
    [HttpPost("login")]
    public async Task<IActionResult> Login()
    {
        var result = await _userSignInManager.PasswordSignInAsync("username", "Password18!", false, false);
        if (result.Succeeded)
        {
            return Ok();
        }
        return BadRequest();
    }
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
            SessionId = Guid.Empty
        };       
        var result = await _userManager.CreateAsync(user, "Password18!");
        
        if (result.Succeeded)
        {
            var roleExist = await _roleManager.RoleExistsAsync("Administrator");
            if (!roleExist)
            { 
                await _roleManager.CreateAsync(new IdentityRole("Administrator"));
            }
            await _userManager.AddToRoleAsync(user, "Administrator");
            return Ok();
        }
        
        const string Issuer = "AuthService";
        var claims = new List<Claim> {
            new Claim(UserClaimTypes.UserSessionId, Guid.Empty.ToString(), ClaimValueTypes.String, Issuer),
        };
        var userIdentity = new ClaimsIdentity(claims, "User");
        var principal = new ClaimsPrincipal(userIdentity);
        //await _userSignInManager.SignInAsync("Cookie", principal);

        return BadRequest();
    }

    [HttpGet]
    [Authorize(Policy = Policies.ELEVATED_RIGHTS)]
    public async Task<IActionResult> Get()
    {
        return Ok();
    }
    
}