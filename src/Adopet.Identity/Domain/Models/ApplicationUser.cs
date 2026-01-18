using Microsoft.AspNetCore.Identity;

namespace Adopet.Domain.Models;

public class ApplicationUser : IdentityUser<Guid>
{
    public bool IsService { get; set; }
    public DateTime CreatedAt { get; set; } =  DateTime.UtcNow;
    public DateTime ModifiedAt { get; set; } =  DateTime.UtcNow;
}