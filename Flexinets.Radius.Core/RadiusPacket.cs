using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Flexinets.Radius.Core
{
    /// <summary>
    /// This class encapsulates a Radius packet and presents it in a more readable form
    /// </summary>
    public class RadiusPacket : IRadiusPacket
    {
        public PacketCode Code
        {
            get;
            internal set;
        }
        public byte Identifier
        {
            get;
            internal set;
        }
        public byte[] Authenticator { get; internal set; } = new byte[16];
        public IDictionary<string, List<object>> Attributes { get; set; } = new Dictionary<string, List<object>>();
        public byte[] SharedSecret
        {
            get;
            internal set;
        }
        public byte[] RequestAuthenticator
        {
            get;
            internal set;
        }


        internal RadiusPacket()
        {
        }


        /// <summary>
        /// Create a new packet with a random authenticator
        /// </summary>
        /// <param name="code"></param>
        /// <param name="identifier"></param>
        /// <param name="secret"></param>
        /// <param name="authenticator">Set authenticator for testing</param>
        public RadiusPacket(PacketCode code, byte identifier, string secret)
        {
            Code = code;
            Identifier = identifier;
            SharedSecret = Encoding.UTF8.GetBytes(secret);

            // Generate random authenticator for access request packets
            if (Code == PacketCode.AccessRequest || Code == PacketCode.StatusServer)
            {
                using (var csp = RandomNumberGenerator.Create())
                {
                    csp.GetNonZeroBytes(Authenticator);
                }
            }

            // A Message authenticator is required in status server packets, calculated last
            if (Code == PacketCode.StatusServer)
            {
                AddAttribute("Message-Authenticator", new byte[16]);
            }
        }


        /// <summary>
        /// Creates a response packet with code, authenticator, identifier and secret from the request packet.
        /// </summary>
        /// <param name="responseCode"></param>
        /// <returns></returns>
        public IRadiusPacket CreateResponsePacket(PacketCode responseCode)
        {
            return new RadiusPacket
            {
                Code = responseCode,
                SharedSecret = SharedSecret,
                Identifier = Identifier,
                RequestAuthenticator = Authenticator
            };
        }


        /// <summary>
        /// Gets a single attribute value with name cast to type
        /// Throws an exception if multiple attributes with the same name are found
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="name"></param>
        /// <returns></returns>
        public T GetAttribute<T>(string name)
        {
            if (Attributes.ContainsKey(name))
            {
                return (T)Attributes[name].Single();
            }

            return default;
        }


        /// <summary>
        /// Gets multiple attribute values with the same name cast to type
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="name"></param>
        /// <returns></returns>
        public List<T> GetAttributes<T>(string name)
        {
            if (Attributes.ContainsKey(name))
            {
                return Attributes[name].Cast<T>().ToList();
            }
            return new List<T>();
        }


        public void AddAttribute(string name, string value)
        {
            AddAttributeObject(name, value);
        }
        public void AddAttribute(string name, uint value)
        {
            AddAttributeObject(name, value);
        }
        public void AddAttribute(string name, IPAddress value)
        {
            AddAttributeObject(name, value);
        }
        public void AddAttribute(string name, byte[] value)
        {
            AddAttributeObject(name, value);
        }

        internal void AddAttributeObject(string name, object value)
        {
            if (!Attributes.ContainsKey(name))
            {
                Attributes.Add(name, new List<object>());
            }
            Attributes[name].Add(value);
        }
    }
}