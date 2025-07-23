
using Application.Extension.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.DataAccess
{
    public class AppDbContext (DbContextOptions<AppDbContext> options): IdentityDbContext<ApplicationUser>(options)
    {
    }
}
