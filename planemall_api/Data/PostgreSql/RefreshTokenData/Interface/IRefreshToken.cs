﻿using planemall_api.Models;

namespace planemall_api.Data.PostgreSql.RefreshTokenData.Interface
{
    public interface IRefreshToken
    {
        Task<IEnumerable<RefreshToken>?> GetAllRefreshTokensAsync();

        Task<RefreshToken?> GetRefreshTokenByIdAsync(int id);

        Task<RefreshToken?> GetRefreshTokenByTokenAsync(string token);

        Task<bool> InsertRefreshTokenAsync(RefreshToken cmd);

        Task<bool> UpdateRefreshTokenAsync(RefreshToken cmd);
    }
}
