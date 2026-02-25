using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace FruitCopyBackTest.Migrations
{
    /// <inheritdoc />
    public partial class playerChanges : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Name",
                table: "Player",
                type: "text",
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Name",
                table: "Player");
        }
    }
}
