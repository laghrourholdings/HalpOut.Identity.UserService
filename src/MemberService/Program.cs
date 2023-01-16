using CommonLibrary.AspNetCore;
using CommonLibrary.AspNetCore.Core;
using Serilog;

var builder = WebApplication.CreateBuilder(args);


var  MyAllowSpecificOrigins = "_myAllowSpecificOrigins";
var logger = new LoggerConfiguration().WriteTo.Console();
builder.Services.AddCommonLibrary(builder.Configuration, builder.Logging, logger , MyAllowSpecificOrigins);
builder.Services.AddCommonLibraryLoggingService();
builder.Services.AddSwaggerGen();
var app = builder.Build();
app.UseCommonLibrary(MyAllowSpecificOrigins);
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.Run();

