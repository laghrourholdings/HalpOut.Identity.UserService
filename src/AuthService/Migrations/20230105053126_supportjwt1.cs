using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthService.Migrations
{
    public partial class supportjwt1 : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "RawAuthenticationTicket",
                table: "UserSessions");

            migrationBuilder.RenameColumn(
                name: "Key",
                table: "UserSessions",
                newName: "CacheKey");

            migrationBuilder.RenameColumn(
                name: "Descriptor",
                table: "UserSessions",
                newName: "Token");

            migrationBuilder.AddColumn<byte[]>(
                name: "PrivateKey",
                table: "UserSessions",
                type: "bytea",
                nullable: true);

            migrationBuilder.AddColumn<byte[]>(
                name: "PublicKey",
                table: "UserSessions",
                type: "bytea",
                nullable: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "PrivateKey",
                table: "UserSessions");

            migrationBuilder.DropColumn(
                name: "PublicKey",
                table: "UserSessions");

            migrationBuilder.RenameColumn(
                name: "Token",
                table: "UserSessions",
                newName: "Descriptor");

            migrationBuilder.RenameColumn(
                name: "CacheKey",
                table: "UserSessions",
                newName: "Key");

            migrationBuilder.AddColumn<byte[]>(
                name: "RawAuthenticationTicket",
                table: "UserSessions",
                type: "bytea",
                nullable: false,
                defaultValue: new byte[0]);
        }
    }
}
