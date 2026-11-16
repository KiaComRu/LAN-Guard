using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace LanGuard.Server;

public sealed class GuardDbFactory : IDesignTimeDbContextFactory<GuardDb>
{
    public GuardDb CreateDbContext(string[] args)
    {
        return new GuardDb(new DbContextOptionsBuilder<GuardDb>().UseSqlite("Data Source=design.db").Options);
    }
}

public sealed class PostgresGuardDbFactory : IDesignTimeDbContextFactory<PostgresGuardDb>
{
    public PostgresGuardDb CreateDbContext(string[] args) =>
        new(new DbContextOptionsBuilder<PostgresGuardDb>()
            .UseNpgsql("Host=localhost;Database=languard;Username=languard").Options);
}
