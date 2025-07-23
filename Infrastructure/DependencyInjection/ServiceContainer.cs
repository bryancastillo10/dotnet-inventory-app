using Application.Extension.Identity;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Infrastructure.DataAccess;

namespace Infrastructure.DependencyInjection
{
    public static class ServiceContainer
    {
        public static IServiceCollection AddInfrastructureService(this IServiceCollection services, IConfiguration config)
        {
            services.AddDbContext<AppDbContext>(opt => opt.UseSqlServer(config.GetConnectionString("Default")), ServiceLifetime.Scoped);

            services.AddAuthentication(opt =>
            {
                opt.DefaultScheme = IdentityConstants.ApplicationScheme;
                opt.DefaultSignInScheme = IdentityConstants.ExternalScheme;
            }).AddIdentityCookies();

            services.AddIdentityCore<ApplicationUser>()
                .AddEntityFrameworkStores<AppDbContext>()
                .AddSignInManager()
                .AddDefaultTokenProviders();

            services.AddAuthorizationBuilder()
                 .AddPolicy("AdministrationPolicy", adp =>
                 {
                     adp.RequireAuthenticatedUser();
                     adp.RequireRole("Admin", "ManagerRole");
                 })
                 .AddPolicy("UserPolicy", adp =>
                 {
                     adp.RequireAuthenticatedUser();
                     adp.RequireRole("User");
                 });

            return services;
        }
    }
}
