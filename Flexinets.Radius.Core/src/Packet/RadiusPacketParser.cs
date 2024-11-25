using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Flexinets.Radius.Core
{
    public partial class RadiusPacketParser : IRadiusPacketParser
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
            bool skipBlastRadiusChecks = true)
        {
            _logger = logger;
            _radiusDictionary = radiusDictionary;
            _skipBlastRadiusChecks = skipBlastRadiusChecks;
        }


        /// <summary>
        /// Parses packet bytes and returns an IRadiusPacket
        /// </summary>
        public IRadiusPacket Parse(byte[] packetBytes, byte[] sharedSecret, byte[] requestAuthenticator = null)
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
                Authenticator = packetBytes.Skip(4).Take(16).ToArray(),
            };

            if ((packet.Code == PacketCode.AccountingRequest || packet.Code == PacketCode.DisconnectRequest) &&
                !packet.Authenticator.SequenceEqual(
                    Utils.CalculateRequestAuthenticator(packet.SharedSecret, packetBytes)))
            {
                throw new InvalidOperationException(
                    $"Invalid request authenticator in packet {packet.Identifier}, check secret?");
            }

            var messageAuthenticatorPosition = AddAttributesToPacket(packet, packetBytes, packetLength);

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
        /// Get the raw packet bytes
        /// </summary>
        public byte[] GetBytes(IRadiusPacket packet)
        {
            var (attributeBytes, messageAuthenticatorPosition) = GetAttributesBytes(packet);

            var packetBytes = new List<byte> { (byte)packet.Code, packet.Identifier, }
                // Populate packet length... Network byte order...
                .Concat(BitConverter.GetBytes((ushort)(20 + attributeBytes.Length)).Reverse())
                .Concat(new byte[16]) // Placeholder for authenticator, will be populated later
                .Concat(attributeBytes) // Populate the attribute value pairs
                .ToArray();

            // Different types of packets have different ways of handling the authenticators
            switch (packet.Code)
            {
                case PacketCode.AccountingRequest:
                case PacketCode.DisconnectRequest:
                case PacketCode.CoaRequest:
                {
                    HandleRequestMessageAuthenticator(packet.SharedSecret, messageAuthenticatorPosition, packetBytes);
                    Buffer.BlockCopy(
                        Utils.CalculateRequestAuthenticator(packet.SharedSecret, packetBytes),
                        0, packetBytes, 4, 16);
                    break;
                }
                case PacketCode.StatusServer:
                case PacketCode.AccessRequest:
                {
                    Buffer.BlockCopy(packet.Authenticator, 0, packetBytes, 4, 16);
                    HandleRequestMessageAuthenticator(packet.SharedSecret, messageAuthenticatorPosition, packetBytes);
                    break;
                }
                case PacketCode.AccessAccept:
                case PacketCode.AccessReject:
                case PacketCode.AccountingResponse:
                case PacketCode.AccessChallenge:
                case PacketCode.StatusClient:
                case PacketCode.DisconnectAck:
                case PacketCode.DisconnectNak:
                case PacketCode.CoaAck:
                case PacketCode.CoaNak:
                default:
                {
                    if (messageAuthenticatorPosition != 0)
                    {
                        var messageAuthenticator = Utils.CalculateResponseMessageAuthenticator(
                            packetBytes,
                            packet.SharedSecret,
                            packet.RequestAuthenticator ?? throw new ArgumentNullException(),
                            messageAuthenticatorPosition);

                        Buffer.BlockCopy(messageAuthenticator, 0, packetBytes, messageAuthenticatorPosition + 2, 16);
                    }

                    var authenticator = Utils.CalculateResponseAuthenticator(
                        packet.SharedSecret,
                        packet.RequestAuthenticator ??
                        throw new ArgumentNullException(nameof(packet.RequestAuthenticator)),
                        packetBytes);

                    Buffer.BlockCopy(authenticator, 0, packetBytes, 4, 16);
                    break;
                }
            }

            return packetBytes;
        }


        /// <summary>
        /// Add a request message authenticator to to the packet if applicable
        /// </summary>
        private static void HandleRequestMessageAuthenticator(byte[] sharedSecret, int messageAuthenticatorPosition,
            byte[] packetBytes)
        {
            if (messageAuthenticatorPosition != 0)
            {
                var messageAuthenticator = Utils.CalculateRequestMessageAuthenticator(
                    packetBytes,
                    sharedSecret,
                    messageAuthenticatorPosition);

                Buffer.BlockCopy(messageAuthenticator, 0, packetBytes, messageAuthenticatorPosition + 2, 16);
            }
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

                    case DictionaryAttribute attributeType:
                        headerBytes[0] = attributeType.Code;

                        // Encrypt password if this is a User-Password attribute
                        if (attributeType.Code == 2)
                        {
                            contentBytes =
                                RadiusPassword.Encrypt(packet.SharedSecret, packet.Authenticator, contentBytes);
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


        /// <summary>
        /// Populate packet with attributes and return position of Message-Authenticator if found
        /// Yees, very mutating... anyway
        /// </summary>
        /// <returns>Message-Authenticator position if found</returns>
        private int AddAttributesToPacket(RadiusPacket packet, byte[] packetBytes, int packetLength)
        {
            var position = 20;
            var messageAuthenticatorPosition = 0;

            while (position < packetLength)
            {
                var typeCode = packetBytes[position];
                var attributeLength = packetBytes[position + 1];
                var attributeValueBytes = packetBytes.Skip(position + 2).Take(attributeLength - 2).ToArray();

                try
                {
                    if (typeCode == 26) // VSA
                    {
                        var vsa = new VendorSpecificAttribute(attributeValueBytes);
                        var vsaType = _radiusDictionary.GetVendorAttribute(vsa.VendorId, vsa.VendorCode);

                        if (vsaType == null)
                        {
                            _logger.LogInformation("Unknown vsa: {id}:{code}", vsa.VendorId, vsa.VendorCode);
                        }
                        else
                        {
                            try
                            {
                                packet.AddAttributeObject(
                                    vsaType.Name,
                                    Attribute.ToObject(
                                        vsa.Value,
                                        vsaType.Type,
                                        typeCode,
                                        packet.Authenticator,
                                        packet.SharedSecret));
                            }
                            catch (Exception ex)
                            {
                                _logger.LogError(ex, "Something went wrong with vsa {name}", vsaType.Name);
                            }
                        }
                    }
                    else
                    {
                        var attributeType = _radiusDictionary.GetAttribute(typeCode) ??
                                            throw new ArgumentNullException(nameof(typeCode));
                        if (attributeType.Code == 80)
                        {
                            messageAuthenticatorPosition = position;
                        }

                        try
                        {
                            packet.AddAttributeObject(
                                attributeType.Name,
                                Attribute.ToObject(
                                    attributeValueBytes,
                                    attributeType.Type,
                                    typeCode,
                                    packet.Authenticator,
                                    packet.SharedSecret));
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "Something went wrong with {attributeTypeName}", attributeType.Name);
                            _logger.LogDebug("Attribute bytes: {hex}", attributeValueBytes.ToHexString());
                        }
                    }
                }
                catch (KeyNotFoundException)
                {
                    _logger.LogWarning("Attribute {typeCode} not found in dictionary", typeCode);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Something went wrong parsing attribute {typeCode}", typeCode);
                }

                position += attributeLength;
            }

            return messageAuthenticatorPosition;
        }
    }
}