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
        private static byte[] EncryptDecrypt(byte[] input, byte[] key) =>
            input.Zip(key, (v, k) => (byte)(v ^ k)).ToArray();


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
            var key = CreateKey(sharedSecret, authenticator);
            var bytes = new List<byte>();
            for (var n = 0; n < passwordBytes.Length / 16; n++)
            {
                var chunk = passwordBytes[(n * 16)..(n * 16 + 16)];
                bytes.AddRange(EncryptDecrypt(chunk, key));
                key = CreateKey(sharedSecret, chunk);
            }

            return Encoding.UTF8.GetString(bytes.ToArray()).Replace("\0", "");
        }


        /// <summary>
        /// Encrypt a password
        /// </summary>´
        public static byte[] Encrypt(byte[] sharedSecret, byte[] authenticator, byte[] passwordBytes)
        {
            Array.Resize(ref passwordBytes, passwordBytes.Length + (16 - passwordBytes.Length % 16));

            var key = CreateKey(sharedSecret, authenticator);
            var bytes = new List<byte>();
            for (var n = 0; n < passwordBytes.Length / 16; n++)
            {
                var xor = EncryptDecrypt(passwordBytes[(n * 16)..(n * 16 + 16)], key);
                bytes.AddRange(xor);
                key = CreateKey(sharedSecret, xor);
            }

            return bytes.ToArray();
        }
    }
}