namespace FruitCopyBackTest.Entities
{
    public class Player
    {
        public Guid Id { get; set; }
        public string LoginKey { get; set; } = "";
        public string Role { get; set; } = "User";
        public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    }
}