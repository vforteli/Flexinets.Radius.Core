using log4net;
using System;
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
        private static readonly ILog _log = LogManager.GetLogger(typeof(RadiusPacket));

        public PacketCode Code
        {
            get;
            private set;
        }
        public Byte Identifier
        {
            get;
            private set;
        }
        public Byte[] Authenticator { get; internal set; } = new Byte[16];
        public IDictionary<String, List<Object>> Attributes { get; set; } = new Dictionary<String, List<Object>>();
        public Byte[] SharedSecret
        {
            get;
            private set;
        }
        private Byte[] _requestAuthenticator;


        private RadiusPacket()
        {
        }


        /// <summary>
        /// Create a new packet with a random authenticator
        /// </summary>
        /// <param name="code"></param>
        /// <param name="identifier"></param>
        /// <param name="secret"></param>
        /// <param name="authenticator">Set authenticator for testing</param>
        public RadiusPacket(PacketCode code, Byte identifier, String secret, Byte[] authenticator = null)
        {
            Code = code;
            Identifier = identifier;
            SharedSecret = Encoding.UTF8.GetBytes(secret);
            Authenticator = authenticator ?? new Byte[16];

            // Generate random authenticator for access request packets
            if (Authenticator == null && (Code == PacketCode.AccessRequest || Code == PacketCode.StatusServer))
            {
                using (var csp = RandomNumberGenerator.Create())
                {
                    csp.GetNonZeroBytes(Authenticator);
                }
            }
        }


        /// <summary>
        /// Parses packet bytes and returns an IRadiusPacket
        /// </summary>
        /// <param name="packetBytes"></param>
        /// <param name="dictionary"></param>
        /// <param name="sharedSecret"></param>
        public static IRadiusPacket Parse(Byte[] packetBytes, RadiusDictionary dictionary, Byte[] sharedSecret)
        {
            // Check the packet length and make sure its valid
            var lengthBytes = new Byte[2];
            lengthBytes[0] = packetBytes[3];
            lengthBytes[1] = packetBytes[2];
            var packetLength = BitConverter.ToUInt16(lengthBytes, 0);
            if (packetBytes.Length != packetLength)
            {
                var message = $"Packet length does not match, expected: {packetLength}, actual: {packetBytes.Length}";
                _log.ErrorFormat(message);
                throw new InvalidOperationException(message);
            }

            var radiusPacket = new RadiusPacket
            {
                SharedSecret = sharedSecret,
                Identifier = packetBytes[1],
                Code = (PacketCode)packetBytes[0],
            };

            Buffer.BlockCopy(packetBytes, 4, radiusPacket.Authenticator, 0, 16);

            if (radiusPacket.Code == PacketCode.AccountingRequest || radiusPacket.Code == PacketCode.DisconnectRequest)
            {
                if (!radiusPacket.Authenticator.SequenceEqual(CalculateRequestAuthenticator(radiusPacket.SharedSecret, packetBytes)))
                {
                    throw new InvalidOperationException($"Invalid request authenticator in packet {radiusPacket.Identifier}, check secret?");
                }
            }

            // The rest are attribute value pairs
            var position = 20;
            while (position < packetBytes.Length)
            {
                var typecode = packetBytes[position];
                var length = packetBytes[position + 1];

                if (position + length > packetLength)
                {
                    throw new ArgumentOutOfRangeException("Go home roamserver, youre drunk");
                }
                var contentBytes = new Byte[length - 2];
                Buffer.BlockCopy(packetBytes, position + 2, contentBytes, 0, length - 2);

                try
                {
                    if (typecode == 26) // VSA
                    {
                        var vsa = new VendorSpecificAttribute(contentBytes);
                        var vendorAttributeDefinition = dictionary.VendorSpecificAttributes.FirstOrDefault(o => o.VendorId == vsa.VendorId && o.VendorCode == vsa.VendorCode);
                        if (vendorAttributeDefinition == null)
                        {
                            _log.Info($"Unknown vsa: {vsa.VendorId}:{vsa.VendorCode}");
                        }
                        else
                        {
                            try
                            {
                                var content = ParseContentBytes(vsa.Value, vendorAttributeDefinition.Type, typecode, radiusPacket.Authenticator, radiusPacket.SharedSecret);
                                radiusPacket.AddAttributeObject(vendorAttributeDefinition.Name, content);
                            }
                            catch (Exception ex)
                            {
                                _log.Error($"Something went wrong with vsa {vendorAttributeDefinition.Name}", ex);
                            }
                        }
                    }
                    else
                    {
                        var attributeDefinition = dictionary.Attributes[typecode];
                        try
                        {
                            var content = ParseContentBytes(contentBytes, attributeDefinition.Type, typecode, radiusPacket.Authenticator, radiusPacket.SharedSecret);
                            radiusPacket.AddAttributeObject(attributeDefinition.Name, content);
                        }
                        catch (Exception ex)
                        {
                            _log.Error($"Something went wrong with {attributeDefinition.Name}", ex);
                        }
                    }
                }
                catch (KeyNotFoundException)
                {
                    _log.Warn($"Attribute {typecode} not found in dictionary");
                }
                catch (Exception ex)
                {
                    _log.Error($"Something went wrong parsing attribute {typecode}", ex);
                }

                position += length;
            }

            return radiusPacket;
        }


        /// <summary>
        /// Parses the content and returns an object of proper type
        /// </summary>
        /// <param name="contentBytes"></param>
        /// <param name="type"></param>
        /// <param name="code"></param>
        /// <param name="authenticator"></param>
        /// <param name="sharedSecret"></param>
        /// <returns></returns>
        private static Object ParseContentBytes(Byte[] contentBytes, String type, UInt32 code, Byte[] authenticator, Byte[] sharedSecret)
        {
            switch (type)
            {
                case "string":
                    return Encoding.UTF8.GetString(contentBytes);

                case "tagged-string":
                    return Encoding.UTF8.GetString(contentBytes);

                case "octet":
                    // If this is a password attribute it must be decrypted
                    if (code == 2)
                    {
                        return RadiusPassword.Decrypt(sharedSecret, authenticator, contentBytes);
                    }
                    return contentBytes;

                case "integer":
                    return BitConverter.ToUInt32(contentBytes.Reverse().ToArray(), 0);

                case "tagged-integer":
                    return BitConverter.ToUInt32(contentBytes.Reverse().ToArray(), 0);

                case "ipaddr":
                    return new IPAddress(contentBytes);

                default:
                    return null;
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
                _requestAuthenticator = Authenticator
            };
        }


        /// <summary>
        /// Gets a single attribute value with name cast to type
        /// Throws an exception if multiple attributes with the same name are found
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="name"></param>
        /// <returns></returns>
        public T GetAttribute<T>(String name)
        {
            if (Attributes.ContainsKey(name))
            {
                return (T)Attributes[name].Single();
            }

            return default(T);
        }


        /// <summary>
        /// Gets multiple attribute values with the same name cast to type
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="name"></param>
        /// <returns></returns>
        public List<T> GetAttributes<T>(String name)
        {
            if (Attributes.ContainsKey(name))
            {
                return Attributes[name].Cast<T>().ToList();
            }
            return new List<T>();
        }


        public void AddAttribute(String name, String value)
        {
            AddAttributeObject(name, value);
        }
        public void AddAttribute(String name, UInt32 value)
        {
            AddAttributeObject(name, value);
        }
        public void AddAttribute(String name, IPAddress value)
        {
            AddAttributeObject(name, value);
        }
        public void AddAttribute(String name, Byte[] value)
        {
            AddAttributeObject(name, value);
        }

        private void AddAttributeObject(String name, Object value)
        {
            if (!Attributes.ContainsKey(name))
            {
                Attributes.Add(name, new List<Object>());
            }
            Attributes[name].Add(value);
        }


        /// <summary>
        /// Get the raw packet bytes
        /// </summary>
        /// <returns></returns>
        public Byte[] GetBytes(RadiusDictionary dictionary)
        {
            var packetBytes = new List<Byte>
            {
                (Byte)Code,
                Identifier
            };
            packetBytes.AddRange(new Byte[18]); // Placeholder for length and authenticator

            foreach (var attribute in Attributes)
            {
                // todo add logic to check attribute object type matches type in dictionary?
                foreach (var value in attribute.Value)
                {
                    var contentBytes = GetAttributeValueBytes(value);
                    var headerBytes = new Byte[2];

                    // Figure out what kind of attribute this is
                    var attributeType = dictionary.Attributes.SingleOrDefault(o => o.Value.Name == attribute.Key);
                    if (dictionary.Attributes.ContainsValue(attributeType.Value))
                    {
                        headerBytes[0] = attributeType.Value.Code;

                        // Encrypt password if this is a User-Password attribute
                        if (attributeType.Value.Code == 2)
                        {
                            contentBytes = RadiusPassword.Encrypt(SharedSecret, Authenticator, contentBytes);
                        }
                    }
                    else
                    {
                        // Maybe this is a vendor attribute?
                        var vendorAttributeType = dictionary.VendorSpecificAttributes.SingleOrDefault(o => o.Name == attribute.Key);
                        if (vendorAttributeType != null)
                        {
                            headerBytes = new Byte[8];
                            headerBytes[0] = 26; // VSA type

                            var vendorId = BitConverter.GetBytes(vendorAttributeType.VendorId);
                            Array.Reverse(vendorId);
                            Buffer.BlockCopy(vendorId, 0, headerBytes, 2, 4);
                            headerBytes[6] = (Byte)vendorAttributeType.VendorCode;
                            headerBytes[7] = (Byte)(2 + contentBytes.Length);  // length of the vsa part
                        }
                        else
                        {
                            _log.Info($"Ignoring unknown attribute {attribute.Key}");
                        }
                    }

                    headerBytes[1] = (Byte)(headerBytes.Length + contentBytes.Length);
                    packetBytes.AddRange(headerBytes);
                    packetBytes.AddRange(contentBytes);
                }
            }

            // Note the order of the bytes...
            var packetLengthBytes = BitConverter.GetBytes(packetBytes.Count);
            packetBytes[2] = packetLengthBytes[1];
            packetBytes[3] = packetLengthBytes[0];

            var packetBytesArray = packetBytes.ToArray();

            if (Code == PacketCode.AccountingRequest || Code == PacketCode.DisconnectRequest)
            {
                var authenticator = CalculateRequestAuthenticator(SharedSecret, packetBytesArray);
                Buffer.BlockCopy(authenticator, 0, packetBytesArray, 4, 16);
            }
            else
            {
                var authenticator = _requestAuthenticator != null ? CalculateResponseAuthenticator(SharedSecret, _requestAuthenticator, packetBytesArray) : Authenticator;
                Buffer.BlockCopy(authenticator, 0, packetBytesArray, 4, 16);
            }


            return packetBytesArray;
        }


        /// <summary>
        /// Gets the byte representation of an attribute object
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        private static Byte[] GetAttributeValueBytes(Object value)
        {
            switch (value)
            {
                case String _value:
                    return Encoding.UTF8.GetBytes(_value);

                case UInt32 _value:
                    var contentBytes = BitConverter.GetBytes(_value);
                    Array.Reverse(contentBytes);
                    return contentBytes;

                case Byte[] _value:
                    return _value;

                case IPAddress _value:
                    return _value.GetAddressBytes();

                default:
                    throw new NotImplementedException();
            }
        }


        /// <summary>
        /// Validates a message authenticator attribute if one exists in the packet
        /// Message-Authenticator = HMAC-MD5 (Type, Identifier, Length, Request Authenticator, Attributes)
        /// The HMAC-MD5 function takes in two arguments:
        /// The payload of the packet, which includes the 16 byte Message-Authenticator field filled with zeros
        /// The shared secret
        /// https://www.ietf.org/rfc/rfc2869.txt
        /// </summary>
        /// <returns></returns>
        public static Byte[] CalculateMessageAuthenticator(IRadiusPacket packet, RadiusDictionary dictionary)
        {
            // Clone the original packet so we can change the message authenticator to zeros
            var checkPacket = Parse(packet.GetBytes(dictionary), dictionary, packet.SharedSecret);
            checkPacket.Attributes["Message-Authenticator"][0] = new Byte[16];

            using (var md5 = new HMACMD5(checkPacket.SharedSecret))
            {
                return md5.ComputeHash(checkPacket.GetBytes(dictionary));
            }
        }


        /// <summary>
        /// Creates a response authenticator
        /// Response authenticator = MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
        /// Actually this means it is the response packet with the request authenticator and secret...
        /// </summary>
        /// <param name="sharedSecret"></param>
        /// <param name="requestAuthenticator"></param>
        /// <param name="packetBytes"></param>
        /// <returns>Response authenticator for the packet</returns>
        private static Byte[] CalculateResponseAuthenticator(Byte[] sharedSecret, Byte[] requestAuthenticator, Byte[] packetBytes)
        {
            var responseAuthenticator = packetBytes.Concat(sharedSecret).ToArray();
            Buffer.BlockCopy(requestAuthenticator, 0, responseAuthenticator, 4, 16);

            using (var md5 = MD5.Create())
            {
                return md5.ComputeHash(responseAuthenticator);
            }
        }


        /// <summary>
        /// Calculate the request authenticator used in accounting and disconnect requests
        /// </summary>
        /// <param name="sharedSecret"></param>
        /// <param name="packetBytes"></param>
        /// <returns></returns>
        public static Byte[] CalculateRequestAuthenticator(Byte[] sharedSecret, Byte[] packetBytes)
        {
            return CalculateResponseAuthenticator(sharedSecret, new Byte[16], packetBytes);
        }
    }
}