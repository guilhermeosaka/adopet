namespace Adopet.Api.Dtos;

public record LoginRequest(string Email, string Password, string? Audience = null);