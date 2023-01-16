using AutoMapper;
using CommonLibrary.AspNetCore.Identity;
using CommonLibrary.AspNetCore.Logging;
using CommonLibrary.Core;
using MassTransit;

namespace MemberService.Identity;

public class UserCreatedConsumer : IConsumer<UserCreated>
{
    private readonly IMapper _mapper;

    public UserCreatedConsumer(
        IMapper mapper,
        IRepository<IObject> repository)
    {
        _mapper = mapper;
    }

    
    public Task Consume(ConsumeContext<UserCreated> context)
    {
        return Task.CompletedTask;
    }
}