using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace SafeVault.Infrastructure.Persistence
{
    public class IdentityDb : IdentityDbContext<IdentityUser, IdentityRole, string>
    {
        public IdentityDb(DbContextOptions<IdentityDb> opts) : base(opts) { }
    }
}

