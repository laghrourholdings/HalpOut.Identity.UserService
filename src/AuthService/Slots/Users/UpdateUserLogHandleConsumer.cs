﻿using CommonLibrary.AspNetCore.Contracts.Users;
using CommonLibrary.AspNetCore.Identity.Model;
using CommonLibrary.AspNetCore.Logging;
using CommonLibrary.AspNetCore.Logging.LoggingService;
using MassTransit;
using Microsoft.AspNetCore.Identity;
using ILogger = Serilog.ILogger;

namespace AuthService.Slots.Users;

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
            _loggingService.ErrorToLogService($"User {userId} not found, can not update", logHandleId);
            return;
        }
        user.LogHandleId = logHandleId;
        var updateResult = await _userManager.UpdateAsync(user);
        if(updateResult.Succeeded)
            return;
        _loggingService.ErrorToLogService($"Can not assign logHandleId {logHandleId} to user {userId}", logHandleId);
    }
}