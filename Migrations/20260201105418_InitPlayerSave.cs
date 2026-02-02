using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace FruitCopyBackTest.Migrations
{
    /// <inheritdoc />
    public partial class InitPlayerSave : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "PlayerSaves",
                columns: table => new
                {
                    PlayerId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    SaveJson = table.Column<string>(type: "text", nullable: false),
                    Version = table.Column<int>(type: "integer", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now() at time zone 'utc'")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PlayerSaves", x => x.PlayerId);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "PlayerSaves");
        }
    }
}
