using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using SafeVault.Application.Services;
using SafeVault.Infrastructure.Persistence;
using SafeVault.Infrastructure.Repositories;
using Xunit;
using Microsoft.Extensions.Configuration;

public class SqlInjectionTests
{
    private static (UserRepository repo, AppDbContext db) Setup()
    {

        var initialData = new Dictionary<string, string?>
        {
            ["EncryptKey"] = "Test-Key-From-InMemory"
        };

        IConfiguration config = new ConfigurationBuilder()
            .AddInMemoryCollection(initialData)
            .Build();

        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase("TestAppDb_" + Guid.NewGuid()).Options;
        var db = new AppDbContext(options);
        var repo = new UserRepository(db, config);
        return (repo, db);
    }

    [Fact]
    public async Task LINQ_Query_DoesNotInject()
    {
        var (repo, db) = Setup();
        db.UserRecords.Add(new SafeVault.Domain.Entities.UserRecord { Username = "admin", Email = "admin@example.com" });
        await db.SaveChangesAsync();

        var service = new SafeVault.Application.Services.UserService(repo);
        var payload = "admin' OR '1'='1";
        var result = await service.FindByUsernameAsync(payload, default);
        Assert.Null(result); // sanitized input becomes 'admin' -> but equals exact match; here result null ensures no "OR 1=1" behavior
    }
}
