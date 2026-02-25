using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace FruitCopyBackTest.Migrations
{
    /// <inheritdoc />
    public partial class PlayerSaveChangesAuth : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropPrimaryKey(
                name: "PK_PlayerSaves",
                table: "PlayerSaves");

            migrationBuilder.DropColumn(
                name: "PlayerId",
                table: "PlayerSaves");

            migrationBuilder.AddColumn<Guid>(
                name: "Id",
                table: "PlayerSaves",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddPrimaryKey(
                name: "PK_PlayerSaves",
                table: "PlayerSaves",
                column: "Id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropPrimaryKey(
                name: "PK_PlayerSaves",
                table: "PlayerSaves");

            migrationBuilder.DropColumn(
                name: "Id",
                table: "PlayerSaves");

            migrationBuilder.AddColumn<string>(
                name: "PlayerId",
                table: "PlayerSaves",
                type: "character varying(64)",
                maxLength: 64,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddPrimaryKey(
                name: "PK_PlayerSaves",
                table: "PlayerSaves",
                column: "PlayerId");
        }
    }
}
