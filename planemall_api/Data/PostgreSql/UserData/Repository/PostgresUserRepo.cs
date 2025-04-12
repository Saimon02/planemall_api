using Microsoft.EntityFrameworkCore;
using planemall_api.Interfaces.Models;
using planemall_api.Models;
using planemall_api.Models.PostgreSql;

namespace planemall_api.Postgresql
{
    public class PostgresUserRepo : IPostgresUser
    {
        private readonly AppDbContext _context;

        private readonly ILogger<PostgresUserRepo> _logger;

        public PostgresUserRepo(AppDbContext context, ILogger<PostgresUserRepo> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task<User?> GetUserByEmailAsync(string email)
        {
            try
            {
                return await _context.Users.FirstOrDefaultAsync(x => x.Email.ToLower() == email.ToLower());
            }
            catch (Exception ex)
            {
                _logger.LogInformation($"Error in GetUserByEmailAsync(), the email is {email}; error details: {ex.Message}");
                return null;
            }
        }

        public async Task<User?> GetUserByIdAsync(int Id)
        {
            try
            {
                return await _context.Users.FirstOrDefaultAsync(x => x.Id == Id);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in GetUserByIdAsync(), the Id is {Id}; error details: {ex.Message}");
                return null;
            }
        }

        public async Task<User?> GetUserByUsernameAsync(string username)
        {
            try
            {
                return await _context.Users.FirstOrDefaultAsync(x => x.Username.ToLower() == username.ToLower());
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in GetUserByUsernameAsync(), the username is {username}; error details: {ex.Message}");
                return null;
            }
        }

        public async Task<bool> InsertUserAsync(User cmd)
        {
            try
            {
                _context.Users.Add(cmd);
                await _context.SaveChangesAsync();
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in InsertUserAsync(); error details: {ex.Message}");
                return false;
            }
        }
    }
}
