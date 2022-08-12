using Auth_JWT.Model;
using System.Threading.Tasks;

namespace Auth_JWT.Repository
{
    public interface IUserRepository
    {
        Task<User> GetUserAsync(string email);
        Task<Session> GetSessionAsync(string email);
        Task<UserResponse> AddUserAsync(string name, string email, string password);
        Task<UserResponse> DeletUserAsync(string email);
        Task<UserResponse> LoginUserAsync(User user);
        Task<UserResponse> LogoutUserAsync(string email);
        Task<User> MakeAdminUser(User user);
    }
}
