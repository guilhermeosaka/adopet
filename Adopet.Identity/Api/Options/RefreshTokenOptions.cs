namespace Adopet.Api.Options;

public class RefreshTokenOptions
{
    public const string Path = "RefreshToken";
    
    public required TimeSpan Expires { get; init; }
}