using System.ComponentModel.DataAnnotations;

namespace FruitCopyBackTest.DTO.Auth
{
    public sealed record RequestOtpDto(
        [Required, MinLength(8), MaxLength(32)] string PhoneOrEmail);

    public sealed record VerifyOtpDto(
        [Required, MinLength(8), MaxLength(32)] string PhoneOrEmail,
        [Required, MinLength(4), MaxLength(8)] string code);

    public sealed record TokenResponseDto(string AccessToken, int ExpiresInSeconds);
}
