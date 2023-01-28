/*using AuthService.Identity;
using AutoMapper;
using CommonLibrary.AspNetCore.Identity;
using CommonLibrary.AspNetCore.Identity.Roles;
using CommonLibrary.Identity.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Core;

public class GrpcUserService : UserService.GrpcUserService.GrpcUserServiceBase
{
    private readonly IMapper _mapper;
    private readonly UserDbContext _dbContext;
    private readonly UserManager<User> _userManager;
    private readonly RoleManager<IdentityRole<Guid>> _roleManager;

    public GrpcUserService(
        IMapper mapper,
        UserDbContext dbContext,
        UserManager<User> userManager,
        RoleManager<IdentityRole<Guid>> roleManager
    )
    {
        _mapper = mapper;
        _dbContext = dbContext;
        _userManager = userManager;
        _roleManager = roleManager;
    }

    public override Task<InvalidateUserResponse>
        Invalidate(InvalidateUserRequest request, ServerCallContext context)
    {
        return base.Invalidate(request, context);
    }

    public override Task<RefreshTokenResponse>
        RefreshToken(RefreshTokenRequest request, ServerCallContext context)
    {
        return base.RefreshToken(request, context);
    }

    public override async Task<GrpcUserBadge>
        RefreshBadge(RefreshBadgeRequest request, ServerCallContext context)
    {
        var token = context.GetHttpContext().Request.Cookies[SecuromanDefaults.TokenCookie];
        var unverifiedUserTicket = Securoman.GetUnverifiedUserTicket(token);
        var ticketClaims = unverifiedUserTicket?.ToList();
        var userId = ticketClaims?.FirstOrDefault(x => x.Type == UserClaimTypes.Id)?.Value;
        var sessionId = ticketClaims?.FirstOrDefault(x => x.Type == UserClaimTypes.SessionId)?.Value;
        if (userId == null || sessionId == null)
            return new GrpcUserBadge();
        var user = _dbContext.Users.Include(x => x.UserSessions).FirstOrDefault(x => x.Id == new Guid(userId));
        //device not included in LINQ request
        if (user == null)
            return new GrpcUserBadge();
        var session = user.UserSessions.FirstOrDefault(s => s.Id == new Guid(sessionId));
        if (session == null || session.IsDeleted)
            return new GrpcUserBadge();
        var verificationResult = Securoman.VerifyToken(token, session.PublicKey);
        if (!verificationResult.Result.IsValid) return new GrpcUserBadge();

        var userRoles = await _userManager.GetRolesAsync(user);
        var rolePrincipal = new RoleIdentity();
        foreach (var userRole in userRoles)
        {
            var role = await _roleManager.FindByNameAsync(userRole);
            if (role == null) continue;
            var roleClaims = await _roleManager.GetClaimsAsync(role);
            foreach (var roleClaim in roleClaims)
                rolePrincipal.Properties.Add(
                    new RoleProperty
                    {
                        /*Issuer = roleClaim.Issuer,#1#
                        Type = roleClaim.Type,
                        Value = roleClaim.Value
                    });
            rolePrincipal.Roles.Add(role.Name);
        }

        var userBadge = new UserBadge
        {
            LogHandleId = user.LogHandleId,
            UserId = user.Id,
            SecretKey = user.SecretKey,
            RoleIdentity = rolePrincipal
        };
        return _mapper.Map<GrpcUserBadge>(userBadge);
    }
}*/