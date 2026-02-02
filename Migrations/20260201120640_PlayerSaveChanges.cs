using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace FruitCopyBackTest.Migrations
{
    /// <inheritdoc />
    public partial class PlayerSaveChanges : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Title",
                table: "PlayerSaves",
                type: "text",
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Title",
                table: "PlayerSaves");
        }
    }
}
