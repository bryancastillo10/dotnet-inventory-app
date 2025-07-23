
using Application.Extension.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.DataAccess
{
    public class DbContext (DbContextOptions<DbContext> options): IdentityDbContext<ApplicationUser>(options)
    {
    }
}
