using SafeVault.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SafeVault.Application.Interfaces
{
    public interface IUserRepository
    {
        Task<UserRecord?> GetByUsernameAsync(string username, CancellationToken ct);
        Task<UserRecord?> GetByEmailAsync(string email, CancellationToken ct);
        Task AddAsync(UserRecord user, CancellationToken ct);
    }
}

