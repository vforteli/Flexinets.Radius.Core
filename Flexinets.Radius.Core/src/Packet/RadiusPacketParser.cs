using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Flexinets.Radius.Core
{
    public class RadiusPacketParser : IRadiusPacketParser
    {
        private readonly ILogger _logger;
        private readonly IRadiusDictionary _radiusDictionary;
        private readonly bool _skipBlastRadiusChecks;


        /// <summary>
        /// RadiusPacketParser
        /// </summary>
        public RadiusPacketParser(
            ILogger<RadiusPacketParser> logger,
            IRadiusDictionary radiusDictionary,
            bool skipBlastRadiusChecks = false)
        {
            _logger = logger;
            _radiusDictionary = radiusDictionary;
            _skipBlastRadiusChecks = skipBlastRadiusChecks;
        }


        /// <summary>
        /// Parses packet bytes and returns an IRadiusPacket
        /// </summary>
        public IRadiusPacket Parse(byte[] packetBytes, byte[] sharedSecret, byte[]? requestAuthenticator = null)
        {
            var packetLength = BitConverter.ToUInt16(packetBytes.Skip(2).Take(2).Reverse().ToArray(), 0);
            if (packetBytes.Length < packetLength)
            {
                throw new ArgumentOutOfRangeException(nameof(packetBytes),
                    $"Packet length mismatch, expected: {packetLength}, actual: {packetBytes.Length}");
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
                if (!packet.Authenticator.SequenceEqual(Utils.CalculateRequestAuthenticator(
                        packet.SharedSecret,
                        packetBytes)))
                {
                    throw new InvalidOperationException(
                        $"Invalid request authenticator in packet {packet.Identifier}, check secret?");
                }
            }

            // The rest are attribute value pairs
            var position = 20;
            var messageAuthenticatorPosition = 0;
            while (position < packetLength)
            {
                var typecode = packetBytes[position];
                var length = packetBytes[position + 1];

                var contentBytes = new byte[length - 2];
                Buffer.BlockCopy(packetBytes, position + 2, contentBytes, 0, length - 2);

                try
                {
                    if (typecode == 26) // VSA
                    {
                        var vsa = new VendorSpecificAttribute(contentBytes);
                        var vendorAttributeDefinition =
                            _radiusDictionary.GetVendorAttribute(vsa.VendorId, vsa.VendorCode);
                        if (vendorAttributeDefinition == null)
                        {
                            _logger.LogInformation($"Unknown vsa: {vsa.VendorId}:{vsa.VendorCode}");
                        }
                        else
                        {
                            try
                            {
                                packet.AddAttributeObject(
                                    vendorAttributeDefinition.Name,
                                    Attribute.ToObject(vsa.Value,
                                        vendorAttributeDefinition.Type,
                                        typecode,
                                        packet.Authenticator,
                                        packet.SharedSecret));
                            }
                            catch (Exception ex)
                            {
                                _logger.LogError(ex, $"Something went wrong with vsa {vendorAttributeDefinition.Name}");
                            }
                        }
                    }
                    else
                    {
                        var attributeDefinition = _radiusDictionary.GetAttribute(typecode) ??
                                                  throw new ArgumentNullException(nameof(typecode));
                        if (attributeDefinition.Code == 80)
                        {
                            messageAuthenticatorPosition = position;
                        }

                        try
                        {
                            packet.AddAttributeObject(
                                attributeDefinition.Name,
                                Attribute.ToObject(contentBytes, attributeDefinition.Type,
                                    typecode,
                                    packet.Authenticator, packet.SharedSecret));
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

            // check blast radius for all Access* packets
            if (packet.Code == PacketCode.AccessAccept
                || packet.Code == PacketCode.AccessChallenge
                || packet.Code == PacketCode.AccessReject
                || packet.Code == PacketCode.AccessRequest)
            {
                if (messageAuthenticatorPosition == 0 && !_skipBlastRadiusChecks)
                {
                    throw new MessageAuthenticatorException("No message authenticator found in packet");
                }

                if (messageAuthenticatorPosition != 20 && !_skipBlastRadiusChecks)
                {
                    _logger.LogWarning("Message authenticator expected to be first attribute");
                }
            }

            if (messageAuthenticatorPosition != 0
                && !Utils.ValidateMessageAuthenticator(
                    packetBytes,
                    packetLength,
                    messageAuthenticatorPosition,
                    sharedSecret,
                    requestAuthenticator))
            {
                throw new MessageAuthenticatorException($"Invalid Message-Authenticator in packet {packet.Identifier}");
            }

            return packet;
        }


        /// <summary>
        /// Tries to get a packet from the stream. Returns true if successful
        /// Returns false if no packet could be parsed or stream is empty ie closing
        /// </summary>
        public bool TryParsePacketFromStream(
            Stream stream,
            out IRadiusPacket? packet,
            byte[] sharedSecret,
            byte[]? requestAuthenticator = null)
        {
            var packetHeaderBytes = new byte[4];
            var i = stream.Read(packetHeaderBytes, 0, 4);
            if (i != 0)
            {
                try
                {
                    var packetLength = BitConverter.ToUInt16(packetHeaderBytes.Reverse().ToArray(), 0);
                    var packetContentBytes = new byte[packetLength - 4];
                    stream.Read(packetContentBytes, 0,
                        packetContentBytes
                            .Length); // todo stream.read should use loop in case everything is not available immediately

                    packet = Parse(packetHeaderBytes.Concat(packetContentBytes).ToArray(), sharedSecret,
                        requestAuthenticator);
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
        /// Get the raw packet bytes
        /// </summary>
        public byte[] GetBytes(IRadiusPacket packet)
        {
            if (packet.SharedSecret == null)
            {
                throw new ArgumentNullException(nameof(packet.SharedSecret));
            }

            var (attributeBytes, messageAuthenticatorPosition) = GetAttributesBytes(packet);

            var packetBytes = new List<byte>
                {
                    (byte)packet.Code,
                    packet.Identifier,
                }
                // Populate packet length... Network byte order...
                .Concat(BitConverter.GetBytes((ushort)(20 + attributeBytes.Length)).Reverse())
                // Placeholder for authenticator, will be populated later
                .Concat(new byte[16])
                // Populate the attribute value pairs
                .Concat(attributeBytes)
                .ToArray();


            // todo refactor this...
            if (packet.Code == PacketCode.AccountingRequest
                || packet.Code == PacketCode.DisconnectRequest
                || packet.Code == PacketCode.CoaRequest)
            {
                if (messageAuthenticatorPosition != 0)
                {
                    var messageAuthenticatorBytes =
                        Utils.CalculateMessageAuthenticator(packetBytes, packet.SharedSecret, null,
                            messageAuthenticatorPosition);

                    Buffer.BlockCopy(messageAuthenticatorBytes, 0, packetBytes, messageAuthenticatorPosition + 2,
                        16);
                }

                var authenticator =
                    Utils.CalculateRequestAuthenticator(packet.SharedSecret, packetBytes);
                Buffer.BlockCopy(authenticator, 0, packetBytes, 4, 16);
            }
            else if (packet.Code == PacketCode.StatusServer || packet.Code == PacketCode.AccessRequest)
            {
                var authenticator = packet.RequestAuthenticator != null
                    ? Utils.CalculateResponseAuthenticator(
                        packet.SharedSecret,
                        packet.RequestAuthenticator,
                        packetBytes)
                    : packet.Authenticator;
                Buffer.BlockCopy(authenticator, 0, packetBytes, 4, 16);

                if (messageAuthenticatorPosition != 0)
                {
                    var messageAuthenticatorBytes = Utils.CalculateMessageAuthenticator(
                        packetBytes,
                        packet.SharedSecret,
                        packet.RequestAuthenticator,
                        messageAuthenticatorPosition);
                    Buffer.BlockCopy(messageAuthenticatorBytes, 0, packetBytes, messageAuthenticatorPosition + 2,
                        16);
                }
            }
            else
            {
                if (messageAuthenticatorPosition != 0)
                {
                    var messageAuthenticatorBytes = Utils.CalculateMessageAuthenticator(
                        packetBytes,
                        packet.SharedSecret,
                        packet.RequestAuthenticator,
                        messageAuthenticatorPosition);

                    Buffer.BlockCopy(messageAuthenticatorBytes, 0, packetBytes, messageAuthenticatorPosition + 2,
                        16);
                }

                var authenticator = packet.RequestAuthenticator != null
                    ? Utils.CalculateResponseAuthenticator(
                        packet.SharedSecret,
                        packet.RequestAuthenticator, packetBytes)
                    : packet.Authenticator;

                Buffer.BlockCopy(authenticator, 0, packetBytes, 4, 16);
            }

            return packetBytes;
        }


        /// <summary>
        /// Get attribute bytes and message authenticator position if found
        /// </summary>
        private (byte[] attributeBytes, int messageAuthenticatorPosition) GetAttributesBytes(IRadiusPacket packet)
        {
            var messageAuthenticatorPosition = 0;
            var currentPosition = 20;

            var attributesBytes = packet.Attributes.SelectMany(a => a.Value.SelectMany(v =>
            {
                var contentBytes = Attribute.ToBytes(v);
                var headerBytes = new byte[2];

                switch (_radiusDictionary.GetAttribute(a.Key))
                {
                    case DictionaryVendorAttribute vendorAttributeType:
                        headerBytes = new byte[8];
                        headerBytes[0] = 26; // VSA type

                        var vendorId = BitConverter.GetBytes(vendorAttributeType.VendorId);
                        Array.Reverse(vendorId);
                        Buffer.BlockCopy(vendorId, 0, headerBytes, 2, 4);
                        headerBytes[6] = (byte)vendorAttributeType.VendorCode;
                        headerBytes[7] = (byte)(2 + contentBytes.Length); // length of the vsa part
                        break;

                    case { } attributeType:
                        headerBytes[0] = attributeType.Code;

                        // Encrypt password if this is a User-Password attribute
                        if (attributeType.Code == 2)
                        {
                            contentBytes = RadiusPassword.Encrypt(
                                packet.SharedSecret ?? throw new ArgumentNullException(nameof(packet.SharedSecret)),
                                packet.Authenticator,
                                contentBytes);
                        }
                        // Remember the position of the message authenticator, because it has to be added after everything else
                        else if (attributeType.Code == 80)
                        {
                            messageAuthenticatorPosition = currentPosition;
                        }

                        break;

                    default:
                        throw new InvalidOperationException(
                            $"Unknown attribute {a.Key}, check spelling or dictionary");
                }

                headerBytes[1] = (byte)(headerBytes.Length + contentBytes.Length);
                var attributeBytes = headerBytes.Concat(contentBytes).ToArray();
                currentPosition += attributeBytes.Length;
                return attributeBytes;
            }));

            return (attributesBytes.ToArray(), messageAuthenticatorPosition);
        }
    }
}