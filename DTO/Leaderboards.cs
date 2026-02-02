using System.ComponentModel.DataAnnotations;

namespace FruitCopyBackTest.DTO.Leaderboards
{
    public sealed record SubmitScoreRequest(
        [Required] Guid PlayerId, 
        long Score
    );

    public sealed record LeaderboardEntryDto(
        Guid PlayerId,
        long Score,
        int Rank,
        DateTimeOffset UpdatedAt
    );

    public sealed record LeaderboardPageResponse(
        string LeaderboardKey,
        int Page,
        int PageSize,
        int Returned,
        LeaderboardEntryDto[] Entries
    );
}
