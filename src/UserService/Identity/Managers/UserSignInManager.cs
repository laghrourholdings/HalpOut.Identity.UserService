﻿using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace AuthService.Identity;

public class UserSignInManager : SignInManager<User>
{
    public UserSignInManager(
        UserManager<User> userManager,
        IHttpContextAccessor contextAccessor,
        IUserClaimsPrincipalFactory<User> claimsFactory,
        IOptions<IdentityOptions> optionsAccessor,
        ILogger<SignInManager<User>> logger,
        IAuthenticationSchemeProvider schemes,
        IUserConfirmation<User> confirmation) : base(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation)
    {
    }
    
    public override Task<SignInResult> PasswordSignInAsync(string userName, string password, bool isPersistent, bool shouldLockout)
    {
        // here goes the external username and password look up
        return base.PasswordSignInAsync(userName, password, isPersistent, shouldLockout);

        if (userName.ToLower() == "username" && password.ToLower() == "password")
        {
            return base.PasswordSignInAsync(userName, password, isPersistent, shouldLockout);
        }
        else
        {
            return Task.FromResult(SignInResult.Failed);
        }
    }
}