namespace Adopet.Domain.Interfaces;

public interface IRefreshTokenRepository
{
    Task<string> CreateAsync(
        Guid userId,
        DateTime expiresAt,
        CancellationToken cancellationToken = default);

    Task<string?> RefreshAsync(
        Guid userId,
        string token,
        DateTime expiresAt,
        CancellationToken cancellationToken = default);

    Task RevokeAsync(string token, CancellationToken cancellationToken = default);

    Task RevokeAllAsync(Guid userId, CancellationToken cancellationToken = default);
}