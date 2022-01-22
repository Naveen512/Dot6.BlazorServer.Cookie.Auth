using Dot6.Bserver.Cookie.Auth.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace Dot6.Bserver.Cookie.Auth.Data;

public class MyCookieAuthContext : DbContext
{
    public MyCookieAuthContext(DbContextOptions<MyCookieAuthContext> context) : base(context)
    {

    }

    public DbSet<Users> Users { get; set; }
    public DbSet<Roles> Roles { get; set; }
    public DbSet<UserRoles> UserRoles { get; set; }
}