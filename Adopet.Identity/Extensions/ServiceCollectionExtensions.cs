using Adopet.Identity.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Adopet.Identity.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddDb(this IServiceCollection services, string? connectionString)
    {
        services
            .AddDbContext<IdentityDbContext>(options => options.UseNpgsql(connectionString))
            .AddIdentity<IdentityUser<Guid>, IdentityRole<Guid>>(options => options.User.RequireUniqueEmail = true)
            .AddEntityFrameworkStores<IdentityDbContext>()
            .AddDefaultTokenProviders();

        return services;
    }
}