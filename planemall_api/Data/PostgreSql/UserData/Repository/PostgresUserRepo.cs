﻿using Microsoft.EntityFrameworkCore;
using planemall_api.Interfaces.Models;
using planemall_api.Models;
using planemall_api.Models.PostgreSql;

namespace planemall_api.Postgresql
{
    public class PostgresUserRepo : IPostgresUser
    {
        private readonly AppDbContext _context;

        public PostgresUserRepo(AppDbContext context)
        {
            _context = context;
        }

        public async Task<User?> GetUserByEmail(string email)
        {
            try
            {
                return await _context.Users.FirstOrDefaultAsync(x => x.Email.ToLower() == email.ToLower());
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        public async Task<User?> GetUserByUsername(string username)
        {
            try
            {
                return await _context.Users.FirstOrDefaultAsync(x => x.Username.ToLower() == username.ToLower());
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        public async Task<bool> InsertUser(User cmd)
        {
            try
            {
                _context.Users.Add(cmd);
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
