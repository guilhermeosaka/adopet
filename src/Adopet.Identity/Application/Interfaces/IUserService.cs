using Microsoft.AspNetCore.Identity;

namespace Adopet.Application.Interfaces;

public interface IUserService<TUser> where TUser : class
{
    Task<IdentityResult> CreateAsync(TUser user, string password);
    Task<TUser?> FindByEmailAsync(string email);
    Task<bool> CheckPasswordAsync(TUser user, string password);
    Task<TUser?> FindByIdAsync(string userId);
}