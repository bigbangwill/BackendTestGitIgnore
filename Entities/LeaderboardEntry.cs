using System.ComponentModel.DataAnnotations;

namespace FruitCopyBackTest.Entities
{
    public class LeaderboardEntry
    {
        [Key]
        public Guid Id { get; set; }

        [Required]
        public Guid LeaderboardId { get; set; }

        [Required]
        public Guid PlayerId { get; set; }

        public long Score;

        public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;

        public Leaderboard? Leaderboard { get; set; }
    }
}