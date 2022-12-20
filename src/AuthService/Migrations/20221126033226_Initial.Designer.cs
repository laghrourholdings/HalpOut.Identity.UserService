﻿// <auto-generated />
using System;
using AuthService.EFCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace AuthService.Migrations
{
    [DbContext(typeof(UserDbContext))]
    [Migration("20221126033226_Initial")]
    partial class Initial
    {
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder
                .HasAnnotation("ProductVersion", "6.0.11")
                .HasAnnotation("Relational:MaxIdentifierLength", 63);

            NpgsqlModelBuilderExtensions.UseIdentityByDefaultColumns(modelBuilder);

            modelBuilder.Entity("CommonLibrary.AspNetCore.Identity.Model.User", b =>
                {
                    b.Property<string>("Id")
                        .HasColumnType("text");

                    b.Property<int>("AccessFailedCount")
                        .HasColumnType("integer");

                    b.Property<string>("ConcurrencyStamp")
                        .IsConcurrencyToken()
                        .HasColumnType("text");

                    b.Property<string>("Email")
                        .HasMaxLength(256)
                        .HasColumnType("character varying(256)");

                    b.Property<bool>("EmailConfirmed")
                        .HasColumnType("boolean");

                    b.Property<bool>("LockoutEnabled")
                        .HasColumnType("boolean");

                    b.Property<DateTimeOffset?>("LockoutEnd")
                        .HasColumnType("timestamp with time zone");

                    b.Property<Guid>("LogHandleId")
                        .HasColumnType("uuid");

                    b.Property<string>("NormalizedEmail")
                        .HasMaxLength(256)
                        .HasColumnType("character varying(256)");

                    b.Property<string>("NormalizedUserName")
                        .HasMaxLength(256)
                        .HasColumnType("character varying(256)");

                    b.Property<string>("PasswordHash")
                        .HasColumnType("text");

                    b.Property<string>("PhoneNumber")
                        .HasColumnType("text");

                    b.Property<bool>("PhoneNumberConfirmed")
                        .HasColumnType("boolean");

                    b.Property<string>("SecurityStamp")
                        .HasColumnType("text");

                    b.Property<bool>("TwoFactorEnabled")
                        .HasColumnType("boolean");

                    b.Property<Guid>("UserDetailId")
                        .HasColumnType("uuid");

                    b.Property<Guid>("UserInterestId")
                        .HasColumnType("uuid");

                    b.Property<string>("UserName")
                        .HasMaxLength(256)
                        .HasColumnType("character varying(256)");

                    b.HasKey("Id");

                    b.HasIndex("NormalizedEmail")
                        .HasDatabaseName("EmailIndex");

                    b.HasIndex("NormalizedUserName")
                        .IsUnique()
                        .HasDatabaseName("UserNameIndex");

                    b.HasIndex("UserDetailId");

                    b.HasIndex("UserInterestId");

                    b.ToTable("AspNetUsers", (string)null);
                });

            modelBuilder.Entity("CommonLibrary.AspNetCore.Identity.Model.UserDetail", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uuid");

                    b.Property<DateTimeOffset?>("BirthDate")
                        .HasColumnType("timestamp with time zone");

                    b.Property<DateTimeOffset>("CreationDate")
                        .HasColumnType("timestamp with time zone");

                    b.Property<string>("Descriptor")
                        .HasColumnType("text");

                    b.Property<string>("Gender")
                        .HasColumnType("text");

                    b.Property<Guid?>("InterestId")
                        .HasColumnType("uuid");

                    b.Property<string>("Locale")
                        .HasColumnType("text");

                    b.Property<string>("Nickname")
                        .HasColumnType("text");

                    b.Property<string>("PictureUrl")
                        .HasColumnType("text");

                    b.Property<bool>("SubscribedToNewsletter")
                        .HasColumnType("boolean");

                    b.Property<string>("UpdatedAt")
                        .HasColumnType("text");

                    b.HasKey("Id");

                    b.ToTable("UserDetails");
                });

            modelBuilder.Entity("CommonLibrary.AspNetCore.Identity.Model.UserDevice", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uuid");

                    b.Property<DateTimeOffset>("CreationDate")
                        .HasColumnType("timestamp with time zone");

                    b.Property<Guid>("DeletedBy")
                        .HasColumnType("uuid");

                    b.Property<DateTimeOffset>("DeletedDate")
                        .HasColumnType("timestamp with time zone");

                    b.Property<string>("Descriptor")
                        .HasColumnType("text");

                    b.Property<string>("DeviceModel")
                        .HasColumnType("text");

                    b.Property<string>("DeviceName")
                        .HasColumnType("text");

                    b.Property<string>("DeviceOs")
                        .HasColumnType("text");

                    b.Property<string>("DeviceType")
                        .HasColumnType("text");

                    b.Property<string>("IpAddress")
                        .HasColumnType("text");

                    b.Property<bool>("IsDeleted")
                        .HasColumnType("boolean");

                    b.Property<bool>("IsSuspended")
                        .HasColumnType("boolean");

                    b.Property<Guid>("SuspendedBy")
                        .HasColumnType("uuid");

                    b.Property<DateTimeOffset>("SuspendedDate")
                        .HasColumnType("timestamp with time zone");

                    b.Property<string>("UserAgent")
                        .HasColumnType("text");

                    b.Property<string>("UserId")
                        .HasColumnType("text");

                    b.HasKey("Id");

                    b.HasIndex("UserId");

                    b.ToTable("UserDevices");
                });

            modelBuilder.Entity("CommonLibrary.AspNetCore.Identity.Model.UserInterest", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uuid");

                    b.Property<DateTimeOffset>("CreationDate")
                        .HasColumnType("timestamp with time zone");

                    b.Property<string>("Descriptor")
                        .HasColumnType("text");

                    b.HasKey("Id");

                    b.ToTable("UserInterests");
                });

            modelBuilder.Entity("CommonLibrary.AspNetCore.Identity.Model.UserSession", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uuid");

                    b.Property<DateTimeOffset>("CreationDate")
                        .HasColumnType("timestamp with time zone");

                    b.Property<Guid>("DeletedBy")
                        .HasColumnType("uuid");

                    b.Property<DateTimeOffset>("DeletedDate")
                        .HasColumnType("timestamp with time zone");

                    b.Property<string>("Descriptor")
                        .HasColumnType("text");

                    b.Property<Guid>("DeviceId")
                        .HasColumnType("uuid");

                    b.Property<DateTimeOffset?>("ExpirationDate")
                        .HasColumnType("timestamp with time zone");

                    b.Property<bool>("IsDeleted")
                        .HasColumnType("boolean");

                    b.Property<string>("Key")
                        .IsRequired()
                        .HasColumnType("text");

                    b.Property<byte[]>("RawAuthenticationTicket")
                        .IsRequired()
                        .HasColumnType("bytea");

                    b.Property<string>("UserId")
                        .HasColumnType("text");

                    b.HasKey("Id");

                    b.HasIndex("DeviceId");

                    b.HasIndex("UserId");

                    b.ToTable("UserSessions");
                });

            modelBuilder.Entity("Microsoft.AspNetCore.Identity.IdentityRole", b =>
                {
                    b.Property<string>("Id")
                        .HasColumnType("text");

                    b.Property<string>("ConcurrencyStamp")
                        .IsConcurrencyToken()
                        .HasColumnType("text");

                    b.Property<string>("Name")
                        .HasMaxLength(256)
                        .HasColumnType("character varying(256)");

                    b.Property<string>("NormalizedName")
                        .HasMaxLength(256)
                        .HasColumnType("character varying(256)");

                    b.HasKey("Id");

                    b.HasIndex("NormalizedName")
                        .IsUnique()
                        .HasDatabaseName("RoleNameIndex");

                    b.ToTable("AspNetRoles", (string)null);
                });

            modelBuilder.Entity("Microsoft.AspNetCore.Identity.IdentityRoleClaim<string>", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("integer");

                    NpgsqlPropertyBuilderExtensions.UseIdentityByDefaultColumn(b.Property<int>("Id"));

                    b.Property<string>("ClaimType")
                        .HasColumnType("text");

                    b.Property<string>("ClaimValue")
                        .HasColumnType("text");

                    b.Property<string>("RoleId")
                        .IsRequired()
                        .HasColumnType("text");

                    b.HasKey("Id");

                    b.HasIndex("RoleId");

                    b.ToTable("AspNetRoleClaims", (string)null);
                });

            modelBuilder.Entity("Microsoft.AspNetCore.Identity.IdentityUserClaim<string>", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("integer");

                    NpgsqlPropertyBuilderExtensions.UseIdentityByDefaultColumn(b.Property<int>("Id"));

                    b.Property<string>("ClaimType")
                        .HasColumnType("text");

                    b.Property<string>("ClaimValue")
                        .HasColumnType("text");

                    b.Property<string>("UserId")
                        .IsRequired()
                        .HasColumnType("text");

                    b.HasKey("Id");

                    b.HasIndex("UserId");

                    b.ToTable("AspNetUserClaims", (string)null);
                });

            modelBuilder.Entity("Microsoft.AspNetCore.Identity.IdentityUserLogin<string>", b =>
                {
                    b.Property<string>("LoginProvider")
                        .HasColumnType("text");

                    b.Property<string>("ProviderKey")
                        .HasColumnType("text");

                    b.Property<string>("ProviderDisplayName")
                        .HasColumnType("text");

                    b.Property<string>("UserId")
                        .IsRequired()
                        .HasColumnType("text");

                    b.HasKey("LoginProvider", "ProviderKey");

                    b.HasIndex("UserId");

                    b.ToTable("AspNetUserLogins", (string)null);
                });

            modelBuilder.Entity("Microsoft.AspNetCore.Identity.IdentityUserRole<string>", b =>
                {
                    b.Property<string>("UserId")
                        .HasColumnType("text");

                    b.Property<string>("RoleId")
                        .HasColumnType("text");

                    b.HasKey("UserId", "RoleId");

                    b.HasIndex("RoleId");

                    b.ToTable("AspNetUserRoles", (string)null);
                });

            modelBuilder.Entity("Microsoft.AspNetCore.Identity.IdentityUserToken<string>", b =>
                {
                    b.Property<string>("UserId")
                        .HasColumnType("text");

                    b.Property<string>("LoginProvider")
                        .HasColumnType("text");

                    b.Property<string>("Name")
                        .HasColumnType("text");

                    b.Property<string>("Value")
                        .HasColumnType("text");

                    b.HasKey("UserId", "LoginProvider", "Name");

                    b.ToTable("AspNetUserTokens", (string)null);
                });

            modelBuilder.Entity("CommonLibrary.AspNetCore.Identity.Model.User", b =>
                {
                    b.HasOne("CommonLibrary.AspNetCore.Identity.Model.UserDetail", "UserDetail")
                        .WithMany()
                        .HasForeignKey("UserDetailId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.HasOne("CommonLibrary.AspNetCore.Identity.Model.UserInterest", "UserInterest")
                        .WithMany()
                        .HasForeignKey("UserInterestId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.Navigation("UserDetail");

                    b.Navigation("UserInterest");
                });

            modelBuilder.Entity("CommonLibrary.AspNetCore.Identity.Model.UserDevice", b =>
                {
                    b.HasOne("CommonLibrary.AspNetCore.Identity.Model.User", null)
                        .WithMany("UserDevices")
                        .HasForeignKey("UserId");
                });

            modelBuilder.Entity("CommonLibrary.AspNetCore.Identity.Model.UserSession", b =>
                {
                    b.HasOne("CommonLibrary.AspNetCore.Identity.Model.UserDevice", "Device")
                        .WithMany()
                        .HasForeignKey("DeviceId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.HasOne("CommonLibrary.AspNetCore.Identity.Model.User", null)
                        .WithMany("UserSessions")
                        .HasForeignKey("UserId");

                    b.Navigation("Device");
                });

            modelBuilder.Entity("Microsoft.AspNetCore.Identity.IdentityRoleClaim<string>", b =>
                {
                    b.HasOne("Microsoft.AspNetCore.Identity.IdentityRole", null)
                        .WithMany()
                        .HasForeignKey("RoleId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();
                });

            modelBuilder.Entity("Microsoft.AspNetCore.Identity.IdentityUserClaim<string>", b =>
                {
                    b.HasOne("CommonLibrary.AspNetCore.Identity.Model.User", null)
                        .WithMany()
                        .HasForeignKey("UserId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();
                });

            modelBuilder.Entity("Microsoft.AspNetCore.Identity.IdentityUserLogin<string>", b =>
                {
                    b.HasOne("CommonLibrary.AspNetCore.Identity.Model.User", null)
                        .WithMany()
                        .HasForeignKey("UserId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();
                });

            modelBuilder.Entity("Microsoft.AspNetCore.Identity.IdentityUserRole<string>", b =>
                {
                    b.HasOne("Microsoft.AspNetCore.Identity.IdentityRole", null)
                        .WithMany()
                        .HasForeignKey("RoleId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.HasOne("CommonLibrary.AspNetCore.Identity.Model.User", null)
                        .WithMany()
                        .HasForeignKey("UserId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();
                });

            modelBuilder.Entity("Microsoft.AspNetCore.Identity.IdentityUserToken<string>", b =>
                {
                    b.HasOne("CommonLibrary.AspNetCore.Identity.Model.User", null)
                        .WithMany()
                        .HasForeignKey("UserId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();
                });

            modelBuilder.Entity("CommonLibrary.AspNetCore.Identity.Model.User", b =>
                {
                    b.Navigation("UserDevices");

                    b.Navigation("UserSessions");
                });
#pragma warning restore 612, 618
        }
    }
}
