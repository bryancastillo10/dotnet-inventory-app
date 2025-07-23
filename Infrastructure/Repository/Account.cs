

using Application.DTO.Request.Identity;
using Application.DTO.Response;
using Application.DTO.Response.Identity;
using Application.Extension.Identity;
using Application.Interface.Identity;
using Infrastructure.DataAccess;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using System.Security.Claims;

namespace Infrastructure.Repository
{
    public class Account
        (UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
    {
        public async Task<ServiceResponse> CreateUserAsync(CreateUserRequestDTO model)
        {
            var user = await FindUserByEmail(model.Email);
            if (user != null)
                return new ServiceResponse(false, "User already exist");

            var newUser = new ApplicationUser()
            {
                UserName = model.Email,
                PasswordHash = model.Password,
                Email = model.Email,
                Name = model.Name
            };

            var result = CheckResult(await userManager.CreateAsync(newUser, model.Password));
            if (!result.Flag)
                return result;
            else
                return await CreateUserClaims(model);
        }

        private async Task<ServiceResponse> CreateUserClaims(CreateUserRequestDTO model)
        {
            if (string.IsNullOrEmpty(model.Policy)) return new ServiceResponse(false, "No policy was specified");
            Claim[] userClaims = [];

            if(model.Policy.Equals(Policy.AdminPolicy, StringComparison.OrdinalIgnoreCase))
            {
                userClaims =
                [
                    new Claim(ClaimTypes.Email, model.Email),
                    new Claim(ClaimTypes.Role, "Admin"),
                    new Claim("Name", model.Name),
                    new Claim("Create", "true"),
                    new Claim("Update", "true"),
                    new Claim("Delete", "true"),
                    new Claim("Read", "true"),
                    new Claim("ManageUser", "true")
                ];

            }
            else if (model.Policy.Equals(Policy.ManagerPolicy, StringComparison.OrdinalIgnoreCase)) 
            {
                userClaims =
                [
                    new Claim(ClaimTypes.Email, model.Email),
                    new Claim(ClaimTypes.Role, "Manager"),
                    new Claim("Name", model.Name),
                    new Claim("Create", "true"),
                    new Claim("Update", "true"),
                    new Claim("Read","true"),
                    new Claim("ManageUser", "false"),
                    new Claim("Delete", "false")
                ];
            }

            else if(model.Policy.Equals(Policy.UserPolicy, StringComparison.OrdinalIgnoreCase))
            {
                userClaims =
                [
                    new Claim(ClaimTypes.Email, model.Email),
                    new Claim(ClaimTypes.Role, "User"),
                    new Claim("Name", model.Name),
                    new Claim("Create", "false"),
                    new Claim("Update", "false"),
                    new Claim("Delete", "false"),
                    new Claim("ManageUser", "false"),
                    new Claim("Read", "false")
                 ];

            }

            var result = CheckResult(await userManager.AddClaimsAsync(await FindUserByEmail(model.Email) ?? throw new InvalidOperationException("User not found"),
                userClaims));
            if (result.Flag)
                return new ServiceResponse(true, "User created");
            else
                return result;
        }


        public async Task<ServiceResponse> LoginAsync(LoginUserRequestDTO model)
        {
            var user = await FindUserByEmail(model.Email);
            if (user == null) return new ServiceResponse(false, "User not found");

            var verifyPassword = await signInManager.CheckPasswordSignInAsync(user, model.Password, false);
            if (!verifyPassword.Succeeded)
                return new ServiceResponse(false, "Incorrect password credentials");

            var result = await signInManager.PasswordSignInAsync(user, model.Password, false, false);
            if (!result.Succeeded)
                return new ServiceResponse(false, "Unknown error occured at login");
            else
                return new ServiceResponse(true, null);

        }
        private async Task<ApplicationUser?> FindUserByEmail(string email)
            => await userManager.FindByEmailAsync(email);

        private async Task<ApplicationUser?> FindUserById(string id)
            => await userManager.FindByIdAsync(id);


        private static ServiceResponse CheckResult(IdentityResult result)
        {
            if (result.Succeeded) return new ServiceResponse(true, null);

            var errors = result.Errors.Select(_ => _.Description);
            return new ServiceResponse(false, string.Join(Environment.NewLine, errors));
        }


        private async Task<IEnumerable<GetUserWithClaimResponseDTO>> GetUsersWithClaimsAsync()
        {
            var UserList = new List<GetUserWithClaimResponseDTO>();
            var allUsers = await userManager.Users.ToListAsync();

            if (allUsers.Count == 0) return UserList;


            foreach (var user in allUsers)
            {
                var currUser = await userManager.FindByIdAsync(user.Id);

                if (currUser == null)
                    continue;

                var getCurrUserClaims = await userManager.GetClaimsAsync(currUser);
                if (getCurrUserClaims.Any())
                {
                    try
                    {
                        UserList.Add(new GetUserWithClaimResponseDTO()
                        {
                            UserId = user.Id,
                            Email = getCurrUserClaims.FirstOrDefault(_ => _.Type == ClaimTypes.Email)?.Value,
                            RoleName = getCurrUserClaims.FirstOrDefault(_ => _.Type == ClaimTypes.Role)?.Value,
                            Name = getCurrUserClaims.FirstOrDefault(_ => _.Type == "Name")?.Value,
                            ManageUser = Convert.ToBoolean(getCurrUserClaims.FirstOrDefault(_ => _.Type == "ManageUser")?.Value ?? "false"),
                            Create = Convert.ToBoolean(getCurrUserClaims.FirstOrDefault(_ => _.Type == "Create")?.Value ?? "false"),
                            Update = Convert.ToBoolean(getCurrUserClaims.FirstOrDefault(_ => _.Type == "Update")?.Value ?? "false"),
                            Delete = Convert.ToBoolean(getCurrUserClaims.FirstOrDefault(_ => _.Type == "Delete")?.Value ?? "false"),
                            Read = Convert.ToBoolean(getCurrUserClaims.FirstOrDefault(_ => _.Type == "Read")?.Value ?? "false")
                        });
                    }
                    catch
                    {
                        continue;
                    }
                }
            }

            return UserList;

        }
    }
}
