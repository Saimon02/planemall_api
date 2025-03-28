using planemall_api.Models;

namespace planemall_api.Interfaces.Models
{
    public interface IPostgresUser
    {
        public Task<bool> InsertUserAsync(User cmd);

        public Task<User?> GetUserByUsernameAsync(string username);

        public Task<User?> GetUserByEmailAsync(string email);

        public Task<User?> GetUserByIdAsync(int Id);
    }
}
