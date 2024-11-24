using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Flexinets.Radius.Core
{
    public static class RadiusPassword
    {
        /// <summary>
        /// Encrypt/decrypt using XOR
        /// </summary>
        private static byte[] EncryptDecrypt(byte[] input, byte[] key)
        {
            var output = new byte[input.Length];
            for (var i = 0; i < input.Length; i++)
            {
                output[i] = (byte)(input[i] ^ key[i]);
            }

            return output;
        }


        /// <summary>
        /// Create a radius shared secret key
        /// </summary>
        private static byte[] CreateKey(byte[] sharedSecret, byte[] authenticator)
        {
            using var md5 = MD5.Create();
            return md5.ComputeHash(sharedSecret.Concat(authenticator).ToArray());
        }


        /// <summary>
        /// Decrypt user password
        /// </summary>
        public static string Decrypt(byte[] sharedSecret, byte[] authenticator, byte[] passwordBytes)
        {
            var sb = new StringBuilder();
            var key = CreateKey(sharedSecret, authenticator);

            for (var n = 1; n <= passwordBytes.Length / 16; n++)
            {
                var temp = new byte[16];
                Buffer.BlockCopy(passwordBytes, (n - 1) * 16, temp, 0, 16);
                sb.Append(Encoding.UTF8.GetString(EncryptDecrypt(temp, key)));
                key = CreateKey(sharedSecret, temp);
            }

            return sb.ToString().Replace("\0", "");
        }


        /// <summary>
        /// Encrypt a password
        /// </summary>´
        public static byte[] Encrypt(byte[] sharedSecret, byte[] authenticator, byte[] passwordBytes)
        {
            Array.Resize(ref passwordBytes, passwordBytes.Length + (16 - (passwordBytes.Length % 16)));

            var key = CreateKey(sharedSecret, authenticator);
            var bytes = new List<byte>();
            for (var n = 1; n <= passwordBytes.Length / 16; n++)
            {
                var temp = new byte[16];
                Buffer.BlockCopy(passwordBytes, (n - 1) * 16, temp, 0, 16);
                var xor = EncryptDecrypt(temp, key);
                bytes.AddRange(xor);
                key = CreateKey(sharedSecret, xor);
            }

            return bytes.ToArray();
        }
    }
}