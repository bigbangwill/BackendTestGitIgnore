using System.ComponentModel.DataAnnotations;

namespace FruitCopyBackTest.Data
{
    public class PlayerSave
    {
        [Key]
        [MaxLength(64)]
        public string PlayerId { get; set; } = default!;

        [Required]
        public string SaveJson { get; set; } = "{}";

        public int Version { get; set; } = 1;

        public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;

        public string Title { get; set; } = string.Empty;
    }
}