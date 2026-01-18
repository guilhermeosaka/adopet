using Adopet.Application.Interfaces;
using Microsoft.AspNetCore.Identity;

namespace Adopet.Infrastructure.Identity;

public class IdentityUserService<TUser>(UserManager<TUser> userManager) : IUserService<TUser> where TUser : class
{
    public Task<IdentityResult> CreateAsync(TUser user, string password) =>
        userManager.CreateAsync(user, password);

    public Task<TUser?> FindByEmailAsync(string email) =>
        userManager.FindByEmailAsync(email);

    public Task<bool> CheckPasswordAsync(TUser user, string password) =>
        userManager.CheckPasswordAsync(user, password);

    public Task<TUser?> FindByIdAsync(string userId) =>
        userManager.FindByIdAsync(userId);
}