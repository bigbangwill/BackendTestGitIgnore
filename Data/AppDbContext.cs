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
        public DbSet<Player> Player => Set<Player>();
        public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

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

            modelBuilder.Entity<RefreshToken>(e =>
            {
                e.HasOne(rt => rt.Player).WithMany().HasForeignKey(rt => rt.PlayerId).OnDelete(DeleteBehavior.Cascade);
                e.HasOne(rt => rt.ReplacedByToken).WithMany().HasForeignKey(rt => rt.ReplacedByTokenId).OnDelete(DeleteBehavior.Restrict);
                e.HasIndex(rt => rt.TokenHash).IsUnique();
                e.HasIndex(rt => new { rt.PlayerId, rt.CreatedAtUtc });
                e.HasIndex(rt => new { rt.PlayerId, rt.ExpiresAtUtc });
            });
        }
    }
}