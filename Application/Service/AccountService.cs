using Application.DTO.Request.Identity;
using Application.DTO.Response;
using Application.DTO.Response.Identity;


namespace Application.Service
{
    public class AccountService (IAccountService account): IAccountService
    {
        public async Task<ServiceResponse> CreateUserAsync(CreateUserRequestDTO model)
            => await account.CreateUserAsync(model);

        public async Task<IEnumerable<GetUserWithClaimResponseDTO>> GetUserWithClaimsAsync()
            => await account.GetUserWithClaimsAsync();

        public async Task<ServiceResponse> LoginAsync(LoginUserRequestDTO model)
            => await account.LoginAsync(model);

        public async Task SetUpAsync() => await account.SetUpAsync();

        public Task<ServiceResponse> UpdateUserAsync(ChangeUserClaimRequestDTO model)
            => account.UpdateUserAsync(model);

        //private async Task<IEnumerable<ActivityTrackerResponseDTO>> GetActivitiesAsync()
        //    => await account.GetActivitiesAsync();

        //public Task SaveActivityAsync(ActivityTrackerResponseDTO model)
        //    => await SaveActivityAsync(model);
    }
}
