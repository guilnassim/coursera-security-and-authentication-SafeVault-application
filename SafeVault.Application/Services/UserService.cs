using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SafeVault.Application.Interfaces;
using SafeVault.Application.Security;
using SafeVault.Domain.Entities;


namespace SafeVault.Application.Services
{
    public class UserService : IUserService
    {
        private readonly IUserRepository _repo;
        public UserService(IUserRepository repo) => _repo = repo;

        public async Task<UserRecord> CreateAsync(string username, string email, string userPrivateDetail, CancellationToken ct)
        {
            var safeUsername = InputSanitizer.SanitizeStrict(username, "-_.");
            var safeEmail = InputSanitizer.SanitizeAndValidateEmail(email);
            var userPrivatedata = InputSanitizer.SanitizeStrict(userPrivateDetail);
            

            if (string.IsNullOrEmpty(safeUsername))
                throw new ArgumentException("Invalid username.");
            if (string.IsNullOrEmpty(safeEmail))
                throw new ArgumentException("Invalid email.");

            var user = new UserRecord { Username = safeUsername, Email = safeEmail , UserPrivateDetail = userPrivateDetail };
            await _repo.AddAsync(user, ct);
            return user;
        }

        public Task<UserRecord?> FindByUsernameAsync(string username, CancellationToken ct)
        {
            var safeUsername = InputSanitizer.SanitizeStrict(username, "-_.");
            return _repo.GetByUsernameAsync(safeUsername, ct);
        }
    }
}

