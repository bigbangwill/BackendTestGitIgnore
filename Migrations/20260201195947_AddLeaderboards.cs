using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace FruitCopyBackTest.Migrations
{
    /// <inheritdoc />
    public partial class AddLeaderboards : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Leaderboards",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Key = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Description = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Leaderboards", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "LeaderboardEntries",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    LeaderboardId = table.Column<Guid>(type: "uuid", nullable: false),
                    PlayerId = table.Column<Guid>(type: "uuid", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    Score = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LeaderboardEntries", x => x.Id);
                    table.ForeignKey(
                        name: "FK_LeaderboardEntries_Leaderboards_LeaderboardId",
                        column: x => x.LeaderboardId,
                        principalTable: "Leaderboards",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_LeaderboardEntries_LeaderboardId_PlayerId",
                table: "LeaderboardEntries",
                columns: new[] { "LeaderboardId", "PlayerId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_LeaderboardEntries_LeaderboardId_Score_UpdatedAt",
                table: "LeaderboardEntries",
                columns: new[] { "LeaderboardId", "Score", "UpdatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_LeaderboardEntries_PlayerId",
                table: "LeaderboardEntries",
                column: "PlayerId");

            migrationBuilder.CreateIndex(
                name: "IX_Leaderboards_Key",
                table: "Leaderboards",
                column: "Key",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "LeaderboardEntries");

            migrationBuilder.DropTable(
                name: "Leaderboards");
        }
    }
}
