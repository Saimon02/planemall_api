using Microsoft.EntityFrameworkCore;
using planemall_api.Data.PostgreSql.RefreshTokenData.Interface;
using planemall_api.Models;
using planemall_api.Models.PostgreSql;

namespace planemall_api.Data.PostgreSql.RefreshTokenData.Repository
{
    public class PostgresRefreshTokenRepo : IPostgresRefreshToken
    {
        private readonly AppDbContext _context;

        public PostgresRefreshTokenRepo(AppDbContext context)
        {
            _context = context;
        }

        public async Task<IEnumerable<RefreshToken>?> GetAllRefreshTokensAsync()
        {
            try
            {
                return await _context.RefreshTokens.ToListAsync();
            }
            catch (Exception ex)
            {
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
                return false;
            }
        }
    }
}
