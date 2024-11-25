using System;
using System.Linq;
using System.Net;
using System.Text;

namespace Flexinets.Radius.Core
{
    public class Attribute
    {
        /// <summary>
        /// Parses the attribute value and returns an object of some sort
        /// </summary>
        public static object ToObject(
            byte[] contentBytes,
            string type,
            uint code,
            byte[] authenticator,
            byte[] sharedSecret)
        {
            switch (type)
            {
                case "string":
                case "tagged-string":
                    return Encoding.UTF8.GetString(contentBytes);
                case "octet" when code == 2:
                    return RadiusPassword.Decrypt(sharedSecret, authenticator, contentBytes);
                case "octet":
                    return contentBytes;
                case "integer":
                case "tagged-integer":
                    return BitConverter.ToUInt32(contentBytes.Reverse().ToArray(), 0);
                case "ipaddr":
                    return new IPAddress(contentBytes);
                default:
                    throw new ArgumentException("Unknown type");
            }
        }


        /// <summary>
        /// Gets the byte representation of an attribute object
        /// </summary>
        public static byte[] ToBytes(object value)
        {
            switch (value)
            {
                case string stringValue:
                    return Encoding.UTF8.GetBytes(stringValue);
                case uint uintValue:
                    return BitConverter.GetBytes(uintValue).Reverse().ToArray();
                case byte[] byteArray:
                    return byteArray;
                case IPAddress ipAddress:
                    return ipAddress.GetAddressBytes();
                default:
                    throw new NotImplementedException();
            }
        }
    }
}