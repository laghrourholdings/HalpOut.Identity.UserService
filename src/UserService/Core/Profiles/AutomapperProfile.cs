/*using AutoMapper;
using CommonLibrary.AspNetCore.Identity;
using CommonLibrary.Logging.Models.Dtos;

namespace AuthService.Core.Profiles;

public class GrpcProfile : Profile
{
    public GrpcProfile()
    {
        // src --> dest
        CreateMap<UserBadge, UserService.GrpcUserBadge>()
            .ForMember(dest=>  dest.UserId, opt=> opt.MapFrom(src=> src.UserId))
            .ForMember(dest=>  dest.LogHandleId, opt=> opt.MapFrom(src=> src.LogHandleId))
            .ForMember(dest=>  dest.SecretKey, opt=> opt.MapFrom(src=> src.SecretKey))
            .ForMember(dest=>  dest.RoleIdentity, opt=> opt.MapFrom(src=> src.RoleIdentity))
            .ForMember(dest=> dest.RoleIdentity.Roles, opt=> opt.MapFrom(src=> src.RoleIdentity.Roles))
            .ForMember(dest=> dest.RoleIdentity.Properties, opt=> opt.MapFrom(src=> src.RoleIdentity.Properties));
    }
}*/