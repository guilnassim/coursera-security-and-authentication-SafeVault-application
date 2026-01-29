using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using SafeVault.Application.Interfaces;
using SafeVault.Domain.Entities;
using SafeVault.Infrastructure.Persistence;

namespace SafeVault.Infrastructure.Repositories
{
    /// <summary>
    /// Uses EF Core LINQ (parameterized under the hood). No raw SQL concatenation.
    /// </summary>
    public class UserRepository : IUserRepository
    {
        private readonly AppDbContext _db;
        private readonly IConfiguration _configuration;
        private const string C_KEYNAME = "EncryptKey";
        public UserRepository(AppDbContext db, IConfiguration configuration) { _db = db; _configuration = configuration; }

        public async Task<UserRecord?> GetByUsernameAsync(string username, CancellationToken ct)
        {
            string key = _configuration[C_KEYNAME];

            if (string.IsNullOrEmpty(key)) { throw new ArgumentNullException(nameof(key), "No key is set in environment variable for Encrypt"); }

            UserRecord userRecord = await _db.UserRecords.AsNoTracking().FirstOrDefaultAsync(u => u.Username == username, ct);

            if (userRecord == null) { return null; }

            userRecord.UserPrivateDetail = Helper.Encryption.Decrypt(userRecord.UserPrivateDetail, key);

            return userRecord;
        }

        public Task<UserRecord?> GetByEmailAsync(string email, CancellationToken ct)
        {
            return _db.UserRecords.AsNoTracking()
                .FirstOrDefaultAsync(u => u.Email == email, ct);
        }

        public async Task AddAsync(UserRecord user, CancellationToken ct)
        {
            string key = _configuration[C_KEYNAME];

            if (string.IsNullOrEmpty(key)) { throw new ArgumentNullException(nameof(key), "No key is set in environment variable for Encrypt"); }

            user.UserPrivateDetail = Helper.Encryption.Encrypt(user.UserPrivateDetail, key);

            await _db.UserRecords.AddAsync(user, ct);
            await _db.SaveChangesAsync(ct);
        }
    }
}
