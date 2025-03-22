using planemall_api.Models;

namespace planemall_api.Interfaces.Models
{
    public interface IPostgresUser
    {
        public Task<bool> InsertUser(User cmd);

        public Task<User?> GetUserByUsername(string username);

        public Task<User?> GetUserByEmail(string email); 
    }
}
