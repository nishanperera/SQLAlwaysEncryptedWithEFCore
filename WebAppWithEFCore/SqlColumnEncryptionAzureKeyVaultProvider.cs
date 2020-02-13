using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;

//https://github.com/dotnet/SqlClient/issues/114
namespace WebAppWithEFCore
{
    public class SqlColumnEncryptionAzureKeyVaultProvider : Microsoft.Data.SqlClient.SqlColumnEncryptionKeyStoreProvider
    {
        private readonly byte[] firstVersion = new byte[1]
        {
      (byte) 1
        };
        public const string ProviderName = "AZURE_KEY_VAULT";
        public readonly string[] TrustedEndPoints;

        public KeyVaultClient KeyVaultClient { get; private set; }

        public SqlColumnEncryptionAzureKeyVaultProvider(
          KeyVaultClient.AuthenticationCallback authenticationCallback)
          : this(authenticationCallback, new string[1]
          {
        "vault.azure.net"
          })
        {
        }

        public SqlColumnEncryptionAzureKeyVaultProvider(
          KeyVaultClient.AuthenticationCallback authenticationCallback,
          string trustedEndPoint)
          : this(authenticationCallback, new string[1]
          {
        trustedEndPoint
          })
        {
        }

        public SqlColumnEncryptionAzureKeyVaultProvider(
          KeyVaultClient.AuthenticationCallback authenticationCallback,
          string[] trustedEndPoints)
        {
            if (authenticationCallback == null)
                throw new ArgumentNullException(nameof(authenticationCallback));
            if (trustedEndPoints == null || trustedEndPoints.Length == 0)
                throw new ArgumentException("trustedEndPoints cannot be null or empty.");
            foreach (string trustedEndPoint in trustedEndPoints)
            {
                if (string.IsNullOrWhiteSpace(trustedEndPoint))
                    throw new ArgumentException(string.Format("Invalid trusted endpoint specified: '{0}'; a trusted endpoint must have a value.", (object)trustedEndPoint));
            }
            this.KeyVaultClient = new KeyVaultClient(authenticationCallback, new DelegatingHandler[0]);
            this.TrustedEndPoints = trustedEndPoints;
        }

        public override byte[] SignColumnMasterKeyMetadata(
          string masterKeyPath,
          bool allowEnclaveComputations)
        {
            return this.AzureKeyVaultSignHashedData(this.ComputeMasterKeyMetadataHash(masterKeyPath, allowEnclaveComputations, false), masterKeyPath);
        }

        public override bool VerifyColumnMasterKeyMetadata(
          string masterKeyPath,
          bool allowEnclaveComputations,
          byte[] signature)
        {
            return this.AzureKeyVaultVerifySignature(this.ComputeMasterKeyMetadataHash(masterKeyPath, allowEnclaveComputations, true), signature, masterKeyPath);
        }

        public override byte[] DecryptColumnEncryptionKey(
          string masterKeyPath,
          string encryptionAlgorithm,
          byte[] encryptedColumnEncryptionKey)
        {
            this.ValidateNonEmptyAKVPath(masterKeyPath, true);
            if (encryptedColumnEncryptionKey == null)
                throw new ArgumentNullException(nameof(encryptedColumnEncryptionKey), "Internal error: Encrypted column encryption key cannot be null.");
            if (encryptedColumnEncryptionKey.Length == 0)
                throw new ArgumentException("Internal error: Empty encrypted column encryption key specified.", nameof(encryptedColumnEncryptionKey));
            this.ValidateEncryptionAlgorithm(ref encryptionAlgorithm, true);
            int akvKeySize = this.GetAKVKeySize(masterKeyPath);
            if ((int)encryptedColumnEncryptionKey[0] != (int)this.firstVersion[0])
                throw new ArgumentException(string.Format((IFormatProvider)CultureInfo.InvariantCulture, "Specified encrypted column encryption key contains an invalid encryption algorithm version '{0}'. Expected version is '{1}'.", (object)encryptedColumnEncryptionKey[0].ToString("X2"), (object)this.firstVersion[0].ToString("X2")), nameof(encryptedColumnEncryptionKey));
            int length1 = this.firstVersion.Length;
            ushort uint16_1 = BitConverter.ToUInt16(encryptedColumnEncryptionKey, length1);
            int startIndex = length1 + 2;
            ushort uint16_2 = BitConverter.ToUInt16(encryptedColumnEncryptionKey, startIndex);
            int srcOffset1 = startIndex + 2 + (int)uint16_1;
            if ((int)uint16_2 != akvKeySize)
                throw new ArgumentException(string.Format((IFormatProvider)CultureInfo.InvariantCulture, "The specified encrypted column encryption key's ciphertext length ({0}) does not match the ciphertext length ({1}) when using column master key (Azure Key Vault key) in '{2}'. The encrypted column encryption key may be corrupt, or the specified Azure Key Vault key path may be incorrect.", (object)uint16_2, (object)akvKeySize, (object)masterKeyPath), nameof(encryptedColumnEncryptionKey));
            int length2 = encryptedColumnEncryptionKey.Length - srcOffset1 - (int)uint16_2;
            if (length2 != akvKeySize)
                throw new ArgumentException(string.Format((IFormatProvider)CultureInfo.InvariantCulture, "The specified encrypted column encryption key's signature length ({0}) does not match the signature length ({1}) when using column master key (Azure Key Vault key) in '{2}'. The encrypted column encryption key may be corrupt, or the specified Azure Key Vault key path may be incorrect.", (object)length2, (object)akvKeySize, (object)masterKeyPath), nameof(encryptedColumnEncryptionKey));
            byte[] encryptedColumnEncryptionKey1 = new byte[(int)uint16_2];
            Buffer.BlockCopy((Array)encryptedColumnEncryptionKey, srcOffset1, (Array)encryptedColumnEncryptionKey1, 0, (int)uint16_2);
            int srcOffset2 = srcOffset1 + (int)uint16_2;
            byte[] signature = new byte[length2];
            Buffer.BlockCopy((Array)encryptedColumnEncryptionKey, srcOffset2, (Array)signature, 0, signature.Length);
            byte[] hash;
            using (var shA256Cng = SHA256.Create())
            {
                shA256Cng.TransformFinalBlock(encryptedColumnEncryptionKey, 0, encryptedColumnEncryptionKey.Length - signature.Length);
                hash = shA256Cng.Hash;
            }
            if (hash == null)
                throw new CryptographicException("Hash should not be null while decrypting encrypted column encryption key.");
            if (!this.AzureKeyVaultVerifySignature(hash, signature, masterKeyPath))
                throw new ArgumentException(string.Format((IFormatProvider)CultureInfo.InvariantCulture, "The specified encrypted column encryption key signature does not match the signature computed with the column master key (Asymmetric key in Azure Key Vault) in '{0}'. The encrypted column encryption key may be corrupt, or the specified path may be incorrect.", (object)masterKeyPath), nameof(encryptedColumnEncryptionKey));
            return this.AzureKeyVaultUnWrap(masterKeyPath, encryptionAlgorithm, encryptedColumnEncryptionKey1);
        }

        public override byte[] EncryptColumnEncryptionKey(
          string masterKeyPath,
          string encryptionAlgorithm,
          byte[] columnEncryptionKey)
        {
            this.ValidateNonEmptyAKVPath(masterKeyPath, false);
            if (columnEncryptionKey == null)
                throw new ArgumentNullException(nameof(columnEncryptionKey), "Internal error: Encrypted column encryption key cannot be null.");
            if (columnEncryptionKey.Length == 0)
                throw new ArgumentException("Empty column encryption key specified.", nameof(columnEncryptionKey));
            this.ValidateEncryptionAlgorithm(ref encryptionAlgorithm, false);
            int akvKeySize = this.GetAKVKeySize(masterKeyPath);
            byte[] numArray1 = new byte[1] { this.firstVersion[0] };
            byte[] bytes1 = Encoding.Unicode.GetBytes(masterKeyPath.ToLowerInvariant());
            byte[] bytes2 = BitConverter.GetBytes((short)bytes1.Length);
            byte[] inputBuffer = this.AzureKeyVaultWrap(masterKeyPath, encryptionAlgorithm, columnEncryptionKey);
            byte[] bytes3 = BitConverter.GetBytes((short)inputBuffer.Length);
            if (inputBuffer.Length != akvKeySize)
                throw new CryptographicException("CipherText length does not match the RSA key size.");
            byte[] hash;
            using (var shA256Cng = SHA256.Create())
            {
                shA256Cng.TransformBlock(numArray1, 0, numArray1.Length, numArray1, 0);
                shA256Cng.TransformBlock(bytes2, 0, bytes2.Length, bytes2, 0);
                shA256Cng.TransformBlock(bytes3, 0, bytes3.Length, bytes3, 0);
                shA256Cng.TransformBlock(bytes1, 0, bytes1.Length, bytes1, 0);
                shA256Cng.TransformFinalBlock(inputBuffer, 0, inputBuffer.Length);
                hash = shA256Cng.Hash;
            }
            byte[] signature = this.AzureKeyVaultSignHashedData(hash, masterKeyPath);
            if (signature.Length != akvKeySize)
                throw new CryptographicException("Signed hash length does not match the RSA key size.");
            if (!this.AzureKeyVaultVerifySignature(hash, signature, masterKeyPath))
                throw new CryptographicException("The specified encrypted column encryption key signature does not match the signature computed with the column master key (Asymmetric key in Azure Key Vault) in '{0}'. The encrypted column encryption key may be corrupt, or the specified path may be incorrect.");
            byte[] numArray2 = new byte[numArray1.Length + bytes3.Length + bytes2.Length + inputBuffer.Length + bytes1.Length + signature.Length];
            int dstOffset1 = 0;
            Buffer.BlockCopy((Array)numArray1, 0, (Array)numArray2, dstOffset1, numArray1.Length);
            int dstOffset2 = dstOffset1 + numArray1.Length;
            Buffer.BlockCopy((Array)bytes2, 0, (Array)numArray2, dstOffset2, bytes2.Length);
            int dstOffset3 = dstOffset2 + bytes2.Length;
            Buffer.BlockCopy((Array)bytes3, 0, (Array)numArray2, dstOffset3, bytes3.Length);
            int dstOffset4 = dstOffset3 + bytes3.Length;
            Buffer.BlockCopy((Array)bytes1, 0, (Array)numArray2, dstOffset4, bytes1.Length);
            int dstOffset5 = dstOffset4 + bytes1.Length;
            Buffer.BlockCopy((Array)inputBuffer, 0, (Array)numArray2, dstOffset5, inputBuffer.Length);
            int dstOffset6 = dstOffset5 + inputBuffer.Length;
            Buffer.BlockCopy((Array)signature, 0, (Array)numArray2, dstOffset6, signature.Length);
            return numArray2;
        }

        private void ValidateEncryptionAlgorithm(ref string encryptionAlgorithm, bool isSystemOp)
        {
            if (encryptionAlgorithm == null)
            {
                if (isSystemOp)
                    throw new ArgumentNullException(nameof(encryptionAlgorithm), "Internal error: Key encryption algorithm cannot be null.");
                throw new ArgumentNullException(nameof(encryptionAlgorithm), "Key encryption algorithm cannot be null.");
            }
            if (encryptionAlgorithm.Equals("RSA_OAEP", StringComparison.OrdinalIgnoreCase))
                encryptionAlgorithm = "RSA-OAEP";
            if (!string.Equals(encryptionAlgorithm, "RSA-OAEP", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException(string.Format((IFormatProvider)CultureInfo.InvariantCulture, "Invalid key encryption algorithm specified: '{0}'. Expected value: '{1}'.", (object)encryptionAlgorithm, (object)"RSA -OAEP"), nameof(encryptionAlgorithm));
        }

        private byte[] ComputeMasterKeyMetadataHash(
          string masterKeyPath,
          bool allowEnclaveComputations,
          bool isSystemOp)
        {
            this.ValidateNonEmptyAKVPath(masterKeyPath, isSystemOp);
            this.GetAKVKeySize(masterKeyPath);
            byte[] bytes = Encoding.Unicode.GetBytes(("AZURE_KEY_VAULT" + masterKeyPath + (object)allowEnclaveComputations).ToLowerInvariant());
            using (var shA256Cng = SHA256.Create())
            {
                shA256Cng.TransformFinalBlock(bytes, 0, bytes.Length);
                return shA256Cng.Hash;
            }
        }

        internal void ValidateNonEmptyAKVPath(string masterKeyPath, bool isSystemOp)
        {
            if (string.IsNullOrWhiteSpace(masterKeyPath))
            {
                string message = masterKeyPath == null ? "Azure Key Vault key path cannot be null." : string.Format((IFormatProvider)CultureInfo.InvariantCulture, "Invalid Azure Key Vault key path specified: '{0}'.", (object)masterKeyPath);
                if (isSystemOp)
                    throw new ArgumentNullException(nameof(masterKeyPath), message);
                throw new ArgumentException(message, nameof(masterKeyPath));
            }
            Uri result;
            if (!Uri.TryCreate(masterKeyPath, UriKind.Absolute, out result))
                throw new ArgumentException(string.Format((IFormatProvider)CultureInfo.InvariantCulture, "Invalid url specified: '{0}'.", (object)masterKeyPath), nameof(masterKeyPath));
            foreach (string trustedEndPoint in this.TrustedEndPoints)
            {
                if (result.Host.EndsWith(trustedEndPoint, StringComparison.OrdinalIgnoreCase))
                    return;
            }
            throw new ArgumentException(string.Format((IFormatProvider)CultureInfo.InvariantCulture, "Invalid Azure Key Vault key path specified: '{0}'. Valid trusted endpoints: {1}.", (object)masterKeyPath, (object)string.Join(", ", ((IEnumerable<string>)this.TrustedEndPoints).ToArray<string>())), nameof(masterKeyPath));
        }

        private byte[] AzureKeyVaultWrap(
          string masterKeyPath,
          string encryptionAlgorithm,
          byte[] columnEncryptionKey)
        {
            if (columnEncryptionKey == null)
                throw new ArgumentNullException(nameof(columnEncryptionKey));
            return Task.Run<KeyOperationResult>((Func<Task<KeyOperationResult>>)(() => KeyVaultClientExtensions.WrapKeyAsync((IKeyVaultClient)this.KeyVaultClient, masterKeyPath, encryptionAlgorithm, columnEncryptionKey, new CancellationToken()))).Result.Result;
        }

        private byte[] AzureKeyVaultUnWrap(
          string masterKeyPath,
          string encryptionAlgorithm,
          byte[] encryptedColumnEncryptionKey)
        {
            if (encryptedColumnEncryptionKey == null)
                throw new ArgumentNullException(nameof(encryptedColumnEncryptionKey));
            if (encryptedColumnEncryptionKey.Length == 0)
                throw new ArgumentException("encryptedColumnEncryptionKey length should not be zero.");
            return Task.Run<KeyOperationResult>((Func<Task<KeyOperationResult>>)(() => KeyVaultClientExtensions.UnwrapKeyAsync((IKeyVaultClient)this.KeyVaultClient, masterKeyPath, encryptionAlgorithm, encryptedColumnEncryptionKey, new CancellationToken()))).Result.Result;
        }

        private byte[] AzureKeyVaultSignHashedData(byte[] dataToSign, string masterKeyPath)
        {
            return Task.Run<KeyOperationResult>((Func<Task<KeyOperationResult>>)(() => KeyVaultClientExtensions.SignAsync((IKeyVaultClient)this.KeyVaultClient, masterKeyPath, "RS256", dataToSign, new CancellationToken()))).Result.Result;
        }

        private bool AzureKeyVaultVerifySignature(
          byte[] dataToVerify,
          byte[] signature,
          string masterKeyPath)
        {
            return Task.Run<bool>((Func<Task<bool>>)(() => KeyVaultClientExtensions.VerifyAsync((IKeyVaultClient)this.KeyVaultClient, masterKeyPath, "RS256", dataToVerify, signature, new CancellationToken()))).Result;
        }

        private int GetAKVKeySize(string masterKeyPath)
        {
            KeyBundle result = Task.Run<KeyBundle>((Func<Task<KeyBundle>>)(() => KeyVaultClientExtensions.GetKeyAsync((IKeyVaultClient)this.KeyVaultClient, masterKeyPath, new CancellationToken()))).Result;
            if (!string.Equals(result.Key.Kty, "RSA", StringComparison.InvariantCultureIgnoreCase) && !string.Equals(result.Key.Kty, "RSA-HSM", StringComparison.InvariantCultureIgnoreCase))
                throw new Exception(string.Format((IFormatProvider)CultureInfo.InvariantCulture, ">Cannot use a non-RSA key: '{0}'.", (object)result.Key.Kty));
            return result.Key.N.Length;
        }
    }
}