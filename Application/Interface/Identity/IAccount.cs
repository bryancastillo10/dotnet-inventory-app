using Application.DTO.Response;
using Application.DTO.Response.ActivityTracker;
using Application.DTO.Response.Identity;
using Application.DTO.Request.ActivityTracker;
using Application.DTO.Request.Identity;

namespace Application.Interface.Identity
{
    public interface IAccount
    {
        Task<ServiceResponse> LoginAsync(LoginRequestDTO model);
        Task<ServiceResponse> CreateUserAsync(CreateUserRequestDTO model);

        Task<IEnumerable<GetUserWithClaimResponseDTO>> GetUserWithClaimsAsync();
        Task SetUpAsync();
        Task<ServiceResponse> UpdateUserAsync(ChangeUserClaimRequestDTO model);
        Task SaveActivityAsync(ActivityTrackerRequestDTO model);

        Task<IEnumerable<ActivityTrackerResponseDTO>> GetActivitiesAsync();

    }
}
