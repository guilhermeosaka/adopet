using System.Security.Cryptography;
using Adopet.Domain.Interfaces;
using Adopet.Domain.Models;
using Microsoft.EntityFrameworkCore;

namespace Adopet.Infrastructure.Repositories;

public class RefreshTokenRepository(IdentityDbContext dbContext) : IRefreshTokenRepository
{
    public async Task<RefreshToken?> GetAsync(string token, CancellationToken cancellationToken = default) => 
        await dbContext.RefreshTokens.FirstOrDefaultAsync(rt =>
            rt.Token == token && !rt.IsRevoked && rt.ExpiresAt > DateTime.UtcNow, cancellationToken);
    
    public async Task<string> CreateAsync(
        Guid userId, 
        DateTime expiresAt, 
        CancellationToken cancellationToken = default)
    {
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        
        await dbContext.RefreshTokens.AddAsync(new RefreshToken
        {
            UserId = userId,
            Token = token,
            ExpiresAt = expiresAt
        }, cancellationToken);
        await dbContext.SaveChangesAsync(cancellationToken);

        return token;
    }

    public async Task<string?> RefreshAsync(
        Guid userId,
        string token, 
        DateTime expiresAt, 
        CancellationToken cancellationToken = default)
    {
        var refreshToken = await dbContext.RefreshTokens.FirstOrDefaultAsync(rt =>
            rt.Token == token && rt.UserId == userId && !rt.IsRevoked && rt.ExpiresAt > DateTime.UtcNow, cancellationToken);
        
        if (refreshToken == null) 
            return null;

        refreshToken.IsRevoked = true;
        
        var newToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        
        await dbContext.RefreshTokens.AddAsync(new RefreshToken
        {
            UserId = userId,
            Token = newToken,
            ExpiresAt = expiresAt
        }, cancellationToken);
        await dbContext.SaveChangesAsync(cancellationToken);

        return newToken;
    }

    public async Task RevokeAsync(string token, CancellationToken cancellationToken = default)
    {
        var refreshToken = await dbContext.RefreshTokens.FirstOrDefaultAsync(rt =>
            rt.Token == token && !rt.IsRevoked, cancellationToken);

        if (refreshToken == null)
            return;
        
        refreshToken.IsRevoked = true;
        
        await dbContext.SaveChangesAsync(cancellationToken);
    }
    
    public async Task RevokeAllAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        await dbContext.RefreshTokens
            .Where(rt => rt.UserId == userId && !rt.IsRevoked)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(rt => rt.IsRevoked, true), 
                cancellationToken: cancellationToken);
    }
}