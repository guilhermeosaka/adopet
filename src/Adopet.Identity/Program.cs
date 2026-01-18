using Adopet.Api.Options;
using Adopet.Application.Interfaces;
using Adopet.Application.Services;
using Adopet.Domain.Interfaces;
using Adopet.Domain.Models;
using Adopet.Extensions;
using Adopet.Infrastructure.Identity;
using Adopet.Infrastructure.Persistence.Repositories;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection(JwtOptions.Path));
builder.Services.Configure<RefreshTokenOptions>(builder.Configuration.GetSection(RefreshTokenOptions.Path));

var jwtOptions = builder.Configuration.GetSection(JwtOptions.Path).Get<JwtOptions>()!;

builder.Services
    .AddEndpointsApiExplorer()
    .AddSwaggerGen()
    .AddDb(builder.Configuration.GetConnectionString("IdentityDb"))
    .AddScoped<IUserService<ApplicationUser>, IdentityUserService<ApplicationUser>>()
    .AddScoped<IRefreshTokenRepository, RefreshTokenRepository>()
    .AddTransient<JwtGenerator>()
    .AddAuthentication(jwtOptions)
    .AddAuthorization();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
