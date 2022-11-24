/*
using System.Security.Claims;
using System.Security.Principal;
using System.Text.Encodings.Web;
using CommonLibrary.AspNetCore.Identity.Model;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace AuthService.Identity.Authentication;

public class UserAuthenticationHandler : AuthenticationHandler<UserAuthenticationOptions>
    {
        public const string Schema = "Identity.UserCookies";
        private const string CookieName = "Identity";

        public UserAuthenticationHandler(
            IOptionsMonitor<UserAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Cookies.ContainsKey(CookieName))
            {
                return AuthenticateResult.Fail("Unauthorized - no \"" + CookieName + "\" header found.");
            }

            // get the value of the authorization header
            string? authorizationHeader = Request.Cookies[CookieName];
            if (string.IsNullOrEmpty(authorizationHeader))
            {
                return AuthenticateResult.NoResult();
            }
            Console.WriteLine(authorizationHeader);

            // snip the schema if it is present
            if (authorizationHeader.StartsWith(Schema, StringComparison.OrdinalIgnoreCase))
            {
                authorizationHeader = authorizationHeader[Schema.Length..];
            }

            // now delegate the actual validation of the string
            try
            {
                return ValidateToken(authorizationHeader.Trim());
            }
            catch (Exception ex)
            {
                return AuthenticateResult.Fail(ex.Message);
            }
        }

        protected AuthenticateResult ValidateToken(string token)
        {
            Console.WriteLine(token);
            
            /*var claims = new List<Claim> {
                new(nameof(user.UserName), user.UserName, ClaimValueTypes.String, Issuer),
                new(UserClaimTypes.UserSessionId, Guid.Empty.ToString(), ClaimValueTypes.String, Issuer),
                new(UserClaimTypes.Previlege, "Administrator", ClaimValueTypes.String, Issuer),
            };
            var identity = new ClaimsIdentity(new List<Claim> {new(ClaimTypes.Name, token)}, Scheme.Name);
            var principal = new GenericPrincipal(identity, Array.Empty<string>());
            var ticket = new AuthenticationTicket(principal, Scheme.Name);
            return AuthenticateResult.Success(ticket);
        }
    }

    public class UserAuthenticationOptions : AuthenticationSchemeOptions
    {
    }*/