using CommonLibrary.AspNetCore;
using CommonLibrary.AspNetCore.Contracts.Objects;
using CommonLibrary.AspNetCore.Contracts.Users;
using CommonLibrary.AspNetCore.Identity.Model;
using CommonLibrary.Core;
using MassTransit;
using Microsoft.AspNetCore.Identity;
using ILogger = Serilog.ILogger;

namespace AuthService.Slots.Users;

public class LogCreateUserResponseConsumer : IConsumer<UpdateUserLogHandle>
{
    
    private readonly UserManager<User> _userManager;
    private readonly ILogger _logger;
    private readonly IConfiguration _config;

    public LogCreateUserResponseConsumer(
        UserManager<User> userManager,
        ILogger logger,
        IConfiguration config)
    {
        _userManager = userManager;
        _logger = logger;
        _config = config;
    }

    
    public async Task Consume(ConsumeContext<UpdateUserLogHandle> context)
    {
        var logContext = context.Message.Payload;
        if (logContext.Subject == null)
        {
            _logger.Error("{@Descriptor} | User is null", logContext);
            return;
        }
        var logHandleId = logContext.Subject.LogHandleId;
        var user = _userManager.Users.SingleOrDefault(x => x.Id == logContext.Subject.Id);
        if (user == null)
        {
            _logger.Error("{@Descriptor} | User not found in db, can not update", logContext);
            return;
        }
        user.LogHandleId = logHandleId;
        var updateResult = await _userManager.UpdateAsync(user);
        if(updateResult.Succeeded)
            return;
        _logger.Error("{@Descriptor} | Can not assign logHandleId to user", logContext);
    }
}