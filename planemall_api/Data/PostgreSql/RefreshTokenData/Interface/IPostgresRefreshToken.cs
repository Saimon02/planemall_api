using planemall_api.Models;

namespace planemall_api.Data.PostgreSql.RefreshTokenData.Interface
{
    public interface IPostgresRefreshToken
    {
        Task<IEnumerable<RefreshToken>?> GetAllRefreshTokensAsync();

        Task<RefreshToken?> GetRefreshTokenByIdAsync(int id);

        Task<bool> InsertRefreshTokenAsync(RefreshToken cmd);

        Task<bool> UpdateRefreshTokenAsync(RefreshToken cmd);
    }
}
