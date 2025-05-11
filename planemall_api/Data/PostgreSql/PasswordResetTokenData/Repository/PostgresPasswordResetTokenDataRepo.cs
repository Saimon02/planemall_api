using Microsoft.EntityFrameworkCore;
using planemall_api.Data.PostgreSql.PasswordResetTokenData.Interface;
using planemall_api.Models;
using planemall_api.Models.PostgreSql;

namespace planemall_api.Data.PostgreSql.PasswordResetTokenData.Repository
{
    public class PostgresPasswordResetTokenDataRepo : IPasswordResetTokenData
    {
        private readonly AppDbContext _context;

        private readonly ILogger<PostgresPasswordResetTokenDataRepo> _logger;

        public PostgresPasswordResetTokenDataRepo(AppDbContext context, ILogger<PostgresPasswordResetTokenDataRepo> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task<IEnumerable<PasswordResetToken>?> GetAllPasswordResetTokensAsync()
        {
            try
            {
                return await _context.PasswordResetTokens.ToListAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in GetAllPasswordResetTokensAsync(); error details: {ex.Message}");
                return null;
            }
        }

        public async Task<IEnumerable<PasswordResetToken>?> GetAllPasswordResetTokensByUserIdAsync(int userId)
        {
            try
            {
                return await _context.PasswordResetTokens.Where(x => x.UserId == userId).ToListAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in GetAllPasswordResetTokensByUserIdAsync(), the userId is {userId}; error details: {ex.Message}");
                return null;
            }
        }

        public async Task<PasswordResetToken?> GetPasswordResetTokenByIdAsync(int id)
        {
            try
            {
                return _context.PasswordResetTokens.FirstOrDefault(x => x.Id == id);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in GetPasswordResetTokenByIdAsync(), the id is {id}; error details: {ex.Message}");
                return null;
            }
        }

        public async Task<bool> InsertPasswordResetTokenAsync(PasswordResetToken cmd)
        {
            try
            {
                _context.PasswordResetTokens.Add(cmd);
                await _context.SaveChangesAsync();
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in InsertPasswordResetTokenAsync(); error details: {ex.Message}");
                return false;
            }
        }

        public async Task<bool> UpdatePasswordResetTokenAsync(PasswordResetToken cmd)
        {
            try
            {
                _context.PasswordResetTokens.Update(cmd);
                await _context.SaveChangesAsync();
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in UpdatePasswordResetTokenAsync(), the cmd.Id is {cmd.Id}; error details: {ex.Message}");
                return false;
            }
        }
    }
}
