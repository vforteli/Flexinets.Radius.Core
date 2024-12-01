using System;
using System.Linq;
using System.Net;
using System.Text;

namespace Flexinets.Radius.Core
{
    public static class Attribute
    {
        /// <summary>
        /// Parses the attribute value and returns an object of some sort
        /// </summary>
        public static object ToObject(
            byte[] contentBytes,
            string type,
            uint code,
            byte[] authenticator,
            byte[] sharedSecret) =>
            type switch
            {
                "string" => Encoding.UTF8.GetString(contentBytes),
                "tagged-string" => Encoding.UTF8.GetString(contentBytes),
                "octet" when code == 2 => RadiusPassword.Decrypt(sharedSecret, authenticator, contentBytes),
                "octet" => contentBytes,
                "integer" => BitConverter.ToUInt32(contentBytes.Reverse().ToArray(), 0),
                "tagged-integer" => BitConverter.ToUInt32(contentBytes.Reverse().ToArray(), 0),
                "ipaddr" => new IPAddress(contentBytes),
                _ => throw new ArgumentException("Unknown type")
            };


        /// <summary>
        /// Gets the byte representation of an attribute object
        /// </summary>
        public static byte[] ToBytes(object value) =>
            value switch
            {
                string stringValue => Encoding.UTF8.GetBytes(stringValue),
                uint uintValue => BitConverter.GetBytes(uintValue).Reverse().ToArray(),
                byte[] byteArray => byteArray,
                IPAddress ipAddress => ipAddress.GetAddressBytes(),
                _ => throw new NotImplementedException()
            };
    }
}