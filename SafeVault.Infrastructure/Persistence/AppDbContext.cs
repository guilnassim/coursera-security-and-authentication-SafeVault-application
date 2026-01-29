using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using SafeVault.Domain.Entities;

namespace SafeVault.Infrastructure.Persistence
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> opts) : base(opts) { }
        public DbSet<UserRecord> UserRecords => Set<UserRecord>();
    }
}
