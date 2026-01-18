namespace Adopet.Api.Options;

public class JwtOptions
{
    public const string Path = "Jwt";
    
    public required string Key { get; init; }
    public required string Issuer { get; init; }
    public required string[] Audiences { get; init; }
    public required TimeSpan UserExpires { get; init; }
    public required TimeSpan ServiceExpires { get; init; }
}