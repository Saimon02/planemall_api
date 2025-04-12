using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json.Linq;
using planemall_api.Data.PostgreSql.RefreshTokenData.Interface;
using planemall_api.Models;
using planemall_api.Models.PostgreSql;

namespace planemall_api.Data.PostgreSql.RefreshTokenData.Repository
{
    public class PostgresRefreshTokenRepo : IPostgresRefreshToken
    {
        private readonly AppDbContext _context;

        private readonly ILogger<PostgresRefreshTokenRepo> _logger;

        public PostgresRefreshTokenRepo(AppDbContext context, ILogger<PostgresRefreshTokenRepo> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task<IEnumerable<RefreshToken>?> GetAllRefreshTokensAsync()
        {
            try
            {
                return await _context.RefreshTokens.ToListAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in GetAllRefreshTokensAsync(); error details: {ex.Message}");
                return null;
            }
        }

        public async Task<RefreshToken?> GetRefreshTokenByIdAsync(int Id)
        {
            try
            {
                return await _context.RefreshTokens.FirstOrDefaultAsync(x => x.Id == Id);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in GetRefreshTokenByIdAsync(), the Id is {Id}; error details: {ex.Message}");
                return null;
            }
        }

        public async Task<RefreshToken?> GetRefreshTokenByTokenAsync(string token)
        {
            try
            {
                return await _context.RefreshTokens.FirstOrDefaultAsync(x => x.Token == token);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in GetRefreshTokenByTokenAsync(), the token is {token}; error details: {ex.Message}");
                return null;
            }
        }

        public async Task<bool> InsertRefreshTokenAsync(RefreshToken cmd)
        {
            try
            {
                _context.RefreshTokens.Add(cmd);
                await _context.SaveChangesAsync();
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in InsertRefreshTokenAsync(); error details: {ex.Message}");
                return false;
            }
        }

        public async Task<bool> UpdateRefreshTokenAsync(RefreshToken cmd)
        {
            try
            {
                _context.RefreshTokens.Update(cmd);
                await _context.SaveChangesAsync();
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in UpdateRefreshTokenAsync(), the cmd.Id is {cmd.Id}; error details: {ex.Message}");
                return false;
            }
        }
    }
}
