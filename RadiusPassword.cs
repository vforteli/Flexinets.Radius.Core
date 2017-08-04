using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Flexinets.Radius.Core
{
    public static class RadiusPassword
    {
        /// <summary>
        /// Encrypt/decrypt using XOR
        /// </summary>
        /// <param name="input"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        private static Byte[] EncryptDecrypt(Byte[] input, Byte[] key)
        {
            var output = new Byte[input.Length];
            for (int i = 0; i < input.Length; i++)
            {
                output[i] = (Byte)(input[i] ^ key[i]);
            }
            return output;
        }


        /// <summary>
        /// Create a radius shared secret key
        /// </summary>
        /// <param name="sharedSecret"></param>
        /// <param name="Stuff"></param>
        /// <returns></returns>
        private static Byte[] CreateKey(Byte[] sharedSecret, Byte[] authenticator)
        {
            var key = new Byte[16 + sharedSecret.Length];
            Buffer.BlockCopy(sharedSecret, 0, key, 0, sharedSecret.Length);
            Buffer.BlockCopy(authenticator, 0, key, sharedSecret.Length, authenticator.Length);

            using (var md5 = MD5.Create())
            {
                return md5.ComputeHash(key);
            }
        }


        /// <summary>
        /// Decrypt user password
        /// </summary>
        /// <param name="sharedSecret"></param>
        /// <param name="authenticator"></param>
        /// <param name="passwordBytes"></param>
        /// <returns></returns>
        public static String Decrypt(Byte[] sharedSecret, Byte[] authenticator, Byte[] passwordBytes)
        {
            var sb = new StringBuilder();
            var key = CreateKey(sharedSecret, authenticator);

            for (var n = 1; n <= passwordBytes.Length / 16; n++)
            {
                var temp = new Byte[16];
                Buffer.BlockCopy(passwordBytes, (n - 1) * 16, temp, 0, 16);
                sb.Append(Encoding.UTF8.GetString(EncryptDecrypt(temp, key)));
                key = CreateKey(sharedSecret, temp);
            }

            return sb.ToString().Replace("\0", "");
        }


        /// <summary>
        /// Encrypt a password
        /// </summary>
        /// <param name="sharedSecret"></param>
        /// <param name="authenticator"></param>
        /// <param name="passwordBytes"></param>
        /// <returns></returns>
        public static Byte[] Encrypt(Byte[] sharedSecret, Byte[] authenticator, Byte[] passwordBytes)
        {
            Array.Resize(ref passwordBytes, passwordBytes.Length + (16 - (passwordBytes.Length % 16)));

            var key = CreateKey(sharedSecret, authenticator);
            var bytes = new List<Byte>();
            for (var n = 1; n <= passwordBytes.Length / 16; n++)
            {
                var temp = new Byte[16];
                Buffer.BlockCopy(passwordBytes, (n - 1) * 16, temp, 0, 16);
                bytes.AddRange(EncryptDecrypt(temp, key));
                key = CreateKey(sharedSecret, temp);
            }

            return bytes.ToArray();
        }
    }
}
