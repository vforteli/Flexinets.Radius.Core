using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Flexinets.Radius.Core
{
    public class RadiusPacketParser : IRadiusPacketParser
    {
        private readonly ILogger _logger;
        private readonly IRadiusDictionary _radiusDictionary;


        /// <summary>
        /// RadiusPacketParser
        /// </summary>
        /// <param name="logger"></param>
        public RadiusPacketParser(ILogger<RadiusPacketParser> logger, IRadiusDictionary radiusDictionary)
        {
            _logger = logger;
            _radiusDictionary = radiusDictionary;
        }


        /// <summary>
        /// Parses packet bytes and returns an IRadiusPacket
        /// </summary>
        /// <param name="packetBytes"></param>
        /// <param name="dictionary"></param>
        /// <param name="sharedSecret"></param>
        public IRadiusPacket Parse(Byte[] packetBytes, Byte[] sharedSecret)
        {
            var packetLength = BitConverter.ToUInt16(packetBytes.Skip(2).Take(2).Reverse().ToArray(), 0);
            if (packetBytes.Length != packetLength)
            {
                throw new InvalidOperationException($"Packet length does not match, expected: {packetLength}, actual: {packetBytes.Length}");
            }

            var packet = new RadiusPacket
            {
                SharedSecret = sharedSecret,
                Identifier = packetBytes[1],
                Code = (PacketCode)packetBytes[0],
            };

            Buffer.BlockCopy(packetBytes, 4, packet.Authenticator, 0, 16);

            if (packet.Code == PacketCode.AccountingRequest || packet.Code == PacketCode.DisconnectRequest)
            {
                if (!packet.Authenticator.SequenceEqual(CalculateRequestAuthenticator(packet.SharedSecret, packetBytes)))
                {
                    throw new InvalidOperationException($"Invalid request authenticator in packet {packet.Identifier}, check secret?");
                }
            }

            // The rest are attribute value pairs
            var position = 20;
            var messageAuthenticatorPosition = 0;
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
                        var vendorAttributeDefinition = _radiusDictionary.GetVendorAttribute(vsa.VendorId, vsa.VendorCode);
                        if (vendorAttributeDefinition == null)
                        {
                            _logger.LogInformation($"Unknown vsa: {vsa.VendorId}:{vsa.VendorCode}");
                        }
                        else
                        {
                            try
                            {
                                var content = ParseContentBytes(vsa.Value, vendorAttributeDefinition.Type, typecode, packet.Authenticator, packet.SharedSecret);
                                packet.AddAttributeObject(vendorAttributeDefinition.Name, content);
                            }
                            catch (Exception ex)
                            {
                                _logger.LogError(ex, $"Something went wrong with vsa {vendorAttributeDefinition.Name}");
                            }
                        }
                    }
                    else
                    {
                        var attributeDefinition = _radiusDictionary.GetAttribute(typecode);
                        if (attributeDefinition.Code == 80)
                        {
                            messageAuthenticatorPosition = position;
                        }
                        try
                        {
                            var content = ParseContentBytes(contentBytes, attributeDefinition.Type, typecode, packet.Authenticator, packet.SharedSecret);
                            packet.AddAttributeObject(attributeDefinition.Name, content);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, $"Something went wrong with {attributeDefinition.Name}");
                            _logger.LogDebug($"Attribute bytes: {contentBytes.ToHexString()}");
                        }
                    }
                }
                catch (KeyNotFoundException)
                {
                    _logger.LogWarning($"Attribute {typecode} not found in dictionary");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, $"Something went wrong parsing attribute {typecode}");
                }

                position += length;
            }

            if (messageAuthenticatorPosition != 0)
            {
                var messageAuthenticator = packet.GetAttribute<Byte[]>("Message-Authenticator");
                var temp = new Byte[16];
                var tempPacket = new Byte[packetBytes.Length];
                packetBytes.CopyTo(tempPacket, 0);
                Buffer.BlockCopy(temp, 0, tempPacket, messageAuthenticatorPosition + 2, 16);
                var calculatedMessageAuthenticator = CalculateMessageAuthenticator(tempPacket, sharedSecret);
                if (!calculatedMessageAuthenticator.SequenceEqual(messageAuthenticator))
                {
                    throw new InvalidOperationException($"Invalid Message-Authenticator in packet {packet.Identifier}");
                }
            }

            return packet;
        }


        /// <summary>
        /// Tries to get a packet from the stream. Returns true if successful
        /// Returns false if no packet could be parsed or stream is empty ie closing
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="packet"></param>
        /// <param name="dictionary"></param>
        /// <returns></returns>
        public Boolean TryParsePacketFromStream(Stream stream, out IRadiusPacket packet, IRadiusDictionary dictionary, Byte[] sharedSecret)
        {
            var packetHeaderBytes = new Byte[4];
            var i = stream.Read(packetHeaderBytes, 0, 4);
            if (i != 0)
            {
                try
                {
                    var packetLength = BitConverter.ToUInt16(packetHeaderBytes.Reverse().ToArray(), 0);
                    var packetContentBytes = new Byte[packetLength - 4];
                    stream.Read(packetContentBytes, 0, packetContentBytes.Length);

                    packet = Parse(packetHeaderBytes.Concat(packetContentBytes).ToArray(), sharedSecret);
                    return true;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Unable to parse packet from stream");
                }
            }

            packet = null;
            return false;
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
        private Object ParseContentBytes(Byte[] contentBytes, String type, UInt32 code, Byte[] authenticator, Byte[] sharedSecret)
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
        /// Validates a message authenticator attribute if one exists in the packet
        /// Message-Authenticator = HMAC-MD5 (Type, Identifier, Length, Request Authenticator, Attributes)
        /// The HMAC-MD5 function takes in two arguments:
        /// The payload of the packet, which includes the 16 byte Message-Authenticator field filled with zeros
        /// The shared secret
        /// https://www.ietf.org/rfc/rfc2869.txt
        /// </summary>
        /// <returns></returns>
        private Byte[] CalculateMessageAuthenticator(Byte[] packetBytes, Byte[] sharedSecret)
        {
            using (var md5 = new HMACMD5(sharedSecret))
            {
                return md5.ComputeHash(packetBytes);
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
        private Byte[] CalculateResponseAuthenticator(Byte[] sharedSecret, Byte[] requestAuthenticator, Byte[] packetBytes)
        {
            var responseAuthenticator = packetBytes.Concat(sharedSecret).ToArray();
            Buffer.BlockCopy(requestAuthenticator, 0, responseAuthenticator, 4, 16);

            using (var md5 = MD5.Create())
            {
                return md5.ComputeHash(responseAuthenticator);
            }
        }


        /// <summary>
        /// Calculate the request authenticator used in accounting, disconnect and coa requests
        /// </summary>
        /// <param name="sharedSecret"></param>
        /// <param name="packetBytes"></param>
        /// <returns></returns>
        internal Byte[] CalculateRequestAuthenticator(Byte[] sharedSecret, Byte[] packetBytes)
        {
            return CalculateResponseAuthenticator(sharedSecret, new Byte[16], packetBytes);
        }


        /// <summary>
        /// Get the raw packet bytes
        /// </summary>
        /// <returns></returns>
        public Byte[] GetBytes(IRadiusPacket packet)
        {
            var packetBytes = new List<Byte>
            {
                (Byte)packet.Code,
                packet.Identifier
            };
            packetBytes.AddRange(new Byte[18]); // Placeholder for length and authenticator

            var messageAuthenticatorPosition = 0;
            foreach (var attribute in packet.Attributes)
            {
                // todo add logic to check attribute object type matches type in dictionary?
                foreach (var value in attribute.Value)
                {
                    var contentBytes = GetAttributeValueBytes(value);
                    var headerBytes = new Byte[2];

                    var attributeType = _radiusDictionary.GetAttribute(attribute.Key);
                    switch (attributeType)
                    {
                        case DictionaryVendorAttribute _attributeType:
                            headerBytes = new Byte[8];
                            headerBytes[0] = 26; // VSA type

                            var vendorId = BitConverter.GetBytes(_attributeType.VendorId);
                            Array.Reverse(vendorId);
                            Buffer.BlockCopy(vendorId, 0, headerBytes, 2, 4);
                            headerBytes[6] = (Byte)_attributeType.VendorCode;
                            headerBytes[7] = (Byte)(2 + contentBytes.Length);  // length of the vsa part
                            break;

                        case DictionaryAttribute _attributeType:
                            headerBytes[0] = attributeType.Code;

                            // Encrypt password if this is a User-Password attribute
                            if (_attributeType.Code == 2)
                            {
                                contentBytes = RadiusPassword.Encrypt(packet.SharedSecret, packet.Authenticator, contentBytes);
                            }
                            else if (_attributeType.Code == 80)    // Remember the position of the message authenticator, because it has to be added after everything else
                            {
                                messageAuthenticatorPosition = packetBytes.Count;
                            }
                            break;

                        default:
                            throw new InvalidOperationException($"Unknown attribute {attribute.Key}, check spelling or dictionary");
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

            if (packet.Code == PacketCode.AccountingRequest || packet.Code == PacketCode.DisconnectRequest || packet.Code == PacketCode.CoaRequest)
            {
                var authenticator = CalculateRequestAuthenticator(packet.SharedSecret, packetBytesArray);
                Buffer.BlockCopy(authenticator, 0, packetBytesArray, 4, 16);
            }
            else
            {
                var authenticator = packet.RequestAuthenticator != null ? CalculateResponseAuthenticator(packet.SharedSecret, packet.RequestAuthenticator, packetBytesArray) : packet.Authenticator;
                Buffer.BlockCopy(authenticator, 0, packetBytesArray, 4, 16);
            }

            if (messageAuthenticatorPosition != 0)
            {
                var temp = new Byte[16];
                Buffer.BlockCopy(temp, 0, packetBytesArray, messageAuthenticatorPosition + 2, 16);
                var messageAuthenticatorBytes = CalculateMessageAuthenticator(packetBytesArray, packet.SharedSecret);
                Buffer.BlockCopy(messageAuthenticatorBytes, 0, packetBytesArray, messageAuthenticatorPosition + 2, 16);
            }


            return packetBytesArray;
        }


        /// <summary>
        /// Gets the byte representation of an attribute object
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        private Byte[] GetAttributeValueBytes(Object value)
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
    }
}
