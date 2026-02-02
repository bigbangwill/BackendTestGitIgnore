using FruitCopyBackTest.Entities;
using Microsoft.EntityFrameworkCore;

namespace FruitCopyBackTest.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        public DbSet<PlayerSave> PlayerSaves => Set<PlayerSave>();
        public DbSet<Leaderboard> Leaderboards => Set<Leaderboard>();
        public DbSet<LeaderboardEntry> LeaderboardEntries => Set<LeaderboardEntry>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<PlayerSave>().Property(x => x.UpdatedAtUtc).HasDefaultValueSql("now() at time zone 'utc'");

            modelBuilder.Entity<Leaderboard>(b =>
            {
                b.HasIndex(x => x.Key).IsUnique();
                b.Property(x => x.Key).IsRequired().HasMaxLength(64);
                b.Property(x => x.Description).HasMaxLength(256);
            });

            modelBuilder.Entity<LeaderboardEntry>(b =>
            {
                b.HasOne(x => x.Leaderboard).WithMany().HasForeignKey(x => x.LeaderboardId).OnDelete(DeleteBehavior.Cascade);
                b.HasIndex(x => new { x.LeaderboardId, x.PlayerId }).IsUnique();
                b.HasIndex(x => new { x.LeaderboardId, x.Score, x.UpdatedAt });
                b.HasIndex(x => x.PlayerId);
            });
        }
    }
}