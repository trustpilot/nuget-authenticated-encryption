namespace AuthenticatedEncryption.Tests
{
    using System;
    using Shouldly;
    using Xunit;

    public class AuthenticatedEncryptionTests
    {
        [Fact]
        public void Encrypt_WhenGivenInput_EncryptsAndDecryptsCorrectly()
        {
            const string Input = "this is a test input string";
            var cryptKey = AuthenticatedEncryption.NewKey();
            var authKey = AuthenticatedEncryption.NewKey();

            var cipherText = AuthenticatedEncryption.Encrypt(Input, cryptKey, authKey);
            var plainText = AuthenticatedEncryption.Decrypt(cipherText, cryptKey, authKey);

            plainText.ShouldBe(Input);
        }

        [Fact]
        public void Encrypt_WhenGivenInput_DecryptsCorrectly()
        {
            const string Input = "this is a test input string";
            const string CipherText = "YGyEXyUEsqCDXvEylo4ZVRWjkAMD+nGd4jhqqbA04VHpnhx2eEEUXjBE5YHCjZP+3nYiodBXWYsjy3UTO6Z8v1XaeeUBgjj6vRcxqNH0HxU=";
            const string CryptKey = "g9hH6MkVnlKlGa5IG+5R/uKgyrCJxOsh5fXlwK0mjH0=";
            const string AuthKey = "oGmd/bHHkd+N6P6lZQxyfikjU7c5P/mhWO/noCsERyY=";
            var cryptKey = Convert.FromBase64String(CryptKey);
            var authKey = Convert.FromBase64String(AuthKey);

            var plainText = AuthenticatedEncryption.Decrypt(CipherText, cryptKey, authKey);

            plainText.ShouldBe(Input);
        }
    }
}
