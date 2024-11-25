using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Flexinets.Radius.Core
{
    public static class Utils
    {
        private static readonly byte[] AuthenticatorZeros = new byte[16];


        /// <summary>
        /// Convert a string of hex encoded bytes to a byte array
        /// </summary>
        public static byte[] StringToByteArray(string hex)
        {
            var numberChars = hex.Length;
            var bytes = new byte[numberChars / 2];
            for (var i = 0; i < numberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }

            return bytes;
        }


        /// <summary>
        /// Convert a byte array to a string of hex encoded bytes
        /// </summary>
        public static string ToHexString(this byte[] bytes) =>
            BitConverter.ToString(bytes).ToLowerInvariant().Replace("-", "");


        /// <summary>
        /// Get the mccmnc as a string from a 3GPP-User-Location-Info vendor attribute.
        /// </summary>
        public static (LocationType locationType, string mccmnc) GetMccMncFrom3GPPLocationInfo(byte[] bytes)
        {
            string mccmnc = null;
            var type = (LocationType)bytes[0];

            if (type == LocationType.CGI
                || type == LocationType.ECGI
                || type == LocationType.RAI
                || type == LocationType.SAI
                || type == LocationType.TAI
                || type == LocationType.TAIAndECGI)
            {
                var mccDigit1 = (bytes[1] & 15).ToString();
                var mccDigit2 = ((bytes[1] & 240) >> 4).ToString();
                var mccDigit3 = (bytes[2] & 15).ToString();

                var mncDigit1 = (bytes[3] & 15).ToString();
                var mncDigit2 = ((bytes[3] >> 4)).ToString();
                var mncDigit3 = (bytes[2] >> 4).ToString();

                mccmnc = mccDigit1 + mccDigit2 + mccDigit3 + mncDigit1 + mncDigit2;
                if (mncDigit3 != "15")
                {
                    mccmnc = mccmnc + mncDigit3;
                }
            }

            return (type, mccmnc);
        }


        /// <summary>
        /// Get message authenticator for a response
        /// Message-Authenticator = HMAC-MD5 (Type, Identifier, Length, Request Authenticator, Attributes)
        /// The HMAC-MD5 function takes in two arguments:
        /// The payload of the packet, which includes the 16 byte Message-Authenticator field filled with zeros
        /// The shared secret
        /// https://www.ietf.org/rfc/rfc2869.txt
        /// </summary>
        /// <param name="packetBytes">Packet bytes with the message authenticator set to zeros</param>
        /// <param name="sharedSecret">Shared secret</param>
        /// <param name="requestAuthenticator">Request authenticator from corresponding request packet</param>
        /// <param name="index">Position of the message authenticator attribute in the packet bytes</param>
        public static byte[] CalculateResponseMessageAuthenticator(byte[] packetBytes, byte[] sharedSecret,
            byte[] requestAuthenticator, int index) =>
            CalculateMessageAuthenticator(packetBytes, sharedSecret, requestAuthenticator, index);


        /// <summary>
        /// Create a message authenticator for a request
        /// Message-Authenticator = HMAC-MD5 (Type, Identifier, Length, Request Authenticator, Attributes)
        /// The HMAC-MD5 function takes in two arguments:
        /// The payload of the packet, which includes the 16 byte Message-Authenticator field filled with zeros
        /// The shared secret
        /// https://www.ietf.org/rfc/rfc2869.txt
        /// </summary>
        /// <param name="packetBytes">Packet bytes with the message authenticator set to zeros</param>
        /// <param name="sharedSecret">Shared secret</param>
        /// <param name="index">Position of the message authenticator attribute in the packet bytes</param>
        public static byte[] CalculateRequestMessageAuthenticator(byte[] packetBytes, byte[] sharedSecret, int index) =>
            CalculateMessageAuthenticator(packetBytes, sharedSecret, null, index);


        private static byte[] CalculateMessageAuthenticator(
            byte[] packetBytes,
            byte[] sharedSecret,
            byte[] requestAuthenticator,
            int index)
        {
            var temp = new byte[packetBytes.Length];
            packetBytes.CopyTo(temp, 0);
            Buffer.BlockCopy(AuthenticatorZeros, 0, temp, index + 2, AuthenticatorZeros.Length);

            requestAuthenticator?.CopyTo(temp, 4);

            using (var md5 = new HMACMD5(sharedSecret))
            {
                return md5.ComputeHash(temp);
            }
        }


        /// <summary>
        /// Creates a response authenticator
        /// Response authenticator = MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
        /// Actually this means it is the response packet with the request authenticator and secret...
        /// </summary>
        /// <returns>Response authenticator for the packet</returns>
        public static byte[] CalculateResponseAuthenticator(
            byte[] sharedSecret,
            byte[] requestAuthenticator,
            byte[] packetBytes)
        {
            var bytes = packetBytes.Concat(sharedSecret).ToArray();
            Buffer.BlockCopy(requestAuthenticator, 0, bytes, 4, 16);

            using (var md5 = MD5.Create())
            {
                return md5.ComputeHash(bytes);
            }
        }


        /// <summary>
        /// Validate message authenticator in packet
        /// </summary>
        public static bool ValidateMessageAuthenticator(
            byte[] packetBytes,
            int packetLength,
            int messageAuthenticatorPosition,
            byte[] sharedSecret,
            byte[] requestAuthenticator)
        {
            var messageAuthenticator = packetBytes.Skip(messageAuthenticatorPosition + 2).Take(16).ToArray();

            var tempPacket = new byte[packetLength];
            Buffer.BlockCopy(packetBytes, 0, tempPacket, 0, packetLength);

            var calculatedMessageAuthenticator = CalculateMessageAuthenticator(
                tempPacket,
                sharedSecret,
                requestAuthenticator,
                messageAuthenticatorPosition);

            return calculatedMessageAuthenticator.SequenceEqual(messageAuthenticator);
        }


        /// <summary>
        /// Calculate the request authenticator used in accounting, disconnect and coa requests
        /// </summary>
        internal static byte[] CalculateRequestAuthenticator(byte[] sharedSecret, byte[] packetBytes) =>
            CalculateResponseAuthenticator(sharedSecret, new byte[16], packetBytes);


        /// <summary>
        /// Get a pretty string representation of the packet
        /// </summary>
        public static string GetPacketString(IRadiusPacket packet)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"Packet dump for {packet.Identifier}:");
            foreach (var attribute in packet.Attributes)
            {
                if (attribute.Key == "User-Password")
                {
                    sb.AppendLine($"{attribute.Key} length : {attribute.Value.First().ToString()?.Length}");
                }
                else
                {
                    attribute.Value.ForEach(o => sb.AppendLine($"{attribute.Key} : {o} [{o.GetType()}]"));
                }
            }

            return sb.ToString();
        }
    }
}