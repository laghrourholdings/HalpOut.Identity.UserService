using CommonLibrary.AspNetCore.Identity.Model;
using CommonLibrary.AspNetCore.Logging.LoggingService;
using CommonLibrary.AspNetCore.ServiceBus.Contracts.Users;
using MassTransit;
using Microsoft.AspNetCore.Identity;

namespace AuthService.ServiceBus.Consumer_Contracts.Users;

public class UpdateUserLogHandleConsumer : IConsumer<UpdateUserLogHandle>
{
    
    private readonly UserManager<User> _userManager;
    private readonly ILoggingService _loggingService;
    private readonly IConfiguration _config;

    public UpdateUserLogHandleConsumer(
        UserManager<User> userManager,
        ILoggingService loggingService,
        IConfiguration config)
    {
        _userManager = userManager;
        _loggingService = loggingService;
        _config = config;
    }

    
    public async Task Consume(ConsumeContext<UpdateUserLogHandle> context)
    {
        var logHandleId = context.Message.LogHandleId;
        var userId = context.Message.UserId;
        var user = _userManager.Users.SingleOrDefault(x => x.Id == context.Message.UserId.ToString());
        if (user == null)
        {
            _loggingService.Error($"User {userId} not found, can not update", logHandleId);
            return;
        }
        user.LogHandleId = logHandleId;
        var updateResult = await _userManager.UpdateAsync(user);
        if(updateResult.Succeeded)
            return;
        _loggingService.Error($"Can not assign logHandleId {logHandleId} to user {userId}", logHandleId);
    }
}