using Microsoft.AspNetCore.Authorization;

namespace AuthService.Identity;

public static class Policies
{
    public const string ELEVATED_RIGHTS = "ElevatedRights";
    public const string AUTHENTICATED = "Authenticated";
    public static AuthorizationOptions UserPolicies(AuthorizationOptions options)
    {
        options.AddPolicy(ELEVATED_RIGHTS, policy =>
            policy.RequireRole("Admin"));
        options.AddPolicy(AUTHENTICATED, policy =>
            policy.RequireAuthenticatedUser());
        return options;
    }
}