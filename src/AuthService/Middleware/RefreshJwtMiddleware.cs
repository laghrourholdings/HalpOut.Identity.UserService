using CommonLibrary.AspNetCore.Logging.LoggingService;

namespace AuthService.Middleware;


public class RefreshJwtMiddleware
{
    private readonly RequestDelegate requestDelegate;
       
    public RefreshJwtMiddleware(RequestDelegate requestDelegate)
    {
        this.requestDelegate = requestDelegate;
          
    }

    public async Task InvokeAsync(HttpContext context, ILoggingService loggingService)
    {
        try
        {
            
            await requestDelegate(context);
        }
        catch (Exception ex)
        {
            context.Response.StatusCode = 500;
            loggingService.Local().Error("Error in RefreshJwtMiddleware: {Ex}", ex);
        }
    }
}



public static class RefreshJwtMiddlewareExtensions
{
    public static IApplicationBuilder UseRefreshJwtMiddleware(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<RefreshJwtMiddleware>();
    }
}