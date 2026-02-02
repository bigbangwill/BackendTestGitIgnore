using System.ComponentModel.DataAnnotations;

namespace FruitCopyBackTest.Entities
{
    public class Leaderboard
    {
        [Key]
        public Guid Id { get; set; }

        [Required, MaxLength(64)]
        public string Key { get; set; } = default!;

        [MaxLength(256)]
        public string? Description { get; set; }

        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    }
}