using SafeVault.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SafeVault.Application.Interfaces
{
    public interface IUserService
    {
        Task<UserRecord> CreateAsync(string username, string email, string userPrivateDetail,CancellationToken ct);
        Task<UserRecord?> FindByUsernameAsync(string username, CancellationToken ct);
    }
}
