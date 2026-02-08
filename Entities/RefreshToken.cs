namespace FruitCopyBackTest.Entities
{
    public class RefreshToken
    {
        public Guid Id { get; set; }
        public Guid PlayerId { get; set; }
        public Player Player { get; set; } = null!;

        public string TokenHash { get;set; } = "";
        public DateTime CreatedAtUtc { get; set; }
        public DateTime ExpiresAtUtc { get; set; }

        public DateTime? RevokedAtUtc { get; set; }
        public string? RevokedReason { get; set; }

        public Guid? ReplacedByTokenId { get; set; }
        public RefreshToken? ReplacedByToken { get; set; }

        public string? CreatedByIp { get; set; }
        public string? RevokedByIp { get; set; }
    }
}
