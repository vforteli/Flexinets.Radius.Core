using System;
using System.Collections.Generic;
using System.Linq;
using Flexinets.Radius.Core.PacketTypes;
using Microsoft.Extensions.Logging;

namespace Flexinets.Radius.Core
{
    public partial class RadiusPacketParser : IRadiusPacketParser
    {
        private readonly ILogger _logger;
        private readonly IRadiusDictionary _dictionary;
        private readonly bool _skipBlastRadiusChecks;


        /// <summary>
        /// RadiusPacketParser
        /// </summary>
        public RadiusPacketParser(
            ILogger<RadiusPacketParser> logger,
            IRadiusDictionary dictionary,
            bool skipBlastRadiusChecks = false)
        {
            _logger = logger;
            _dictionary = dictionary;
            _skipBlastRadiusChecks = skipBlastRadiusChecks;
        }


        /// <summary>
        /// Parses packet bytes and returns an IRadiusPacket
        /// </summary>
        public IRadiusPacket Parse(byte[] packetBytes, byte[] sharedSecret, byte[]? requestAuthenticator = null)
        {
            var (packet, messageAuthenticatorPosition) = ParsePacketBytes(ref packetBytes, sharedSecret);

            // Validate RequestAuthenticator for appropriate packet types
            if ((packet is AccountingRequest
                 || packet is DisconnectRequest
                 || packet is CoaRequest) && !packet.Authenticator.SequenceEqual(
                    Utils.CalculateRequestAuthenticator(sharedSecret, packetBytes)))
            {
                throw new InvalidOperationException(
                    $"Invalid request authenticator in packet {packet.Identifier}, check secret?");
            }

            // If the packet contains a Message-Authenticator it must be valid regardless of if it is required
            if (messageAuthenticatorPosition != 0
                && !Utils.ValidateMessageAuthenticator(
                    packetBytes,
                    messageAuthenticatorPosition,
                    sharedSecret,
                    requestAuthenticator))
            {
                throw new InvalidMessageAuthenticatorException(
                    $"Invalid Message-Authenticator in packet {packet.Identifier}");
            }

            if (packet is AccessAccept
                || packet is AccessChallenge
                || packet is AccessReject
                || packet is AccessRequest)
            {
                // Ensure packet contains a Message-Authenticator if it contains EAP-Message attributes                                 
                // https://datatracker.ietf.org/doc/html/rfc3579#section-3.1
                if (messageAuthenticatorPosition == 0 && packet.GetAttributes<object>("EAP-Message").Any())
                {
                    throw new MissingMessageAuthenticatorException(
                        "No Message-Authenticator found in packet with EAP-Message attributes");
                }

                // Ensure a Message-Authenticator exists in Access* packets
                // https://datatracker.ietf.org/doc/html/draft-ietf-radext-deprecating-radius/#section-5
                if (messageAuthenticatorPosition == 0 && !_skipBlastRadiusChecks)
                {
                    throw new MissingMessageAuthenticatorException(
                        "No Message-Authenticator found in packet and BLASTRadius checks enabled");
                }

                // The Message-Authenticator attribute should be first in AccessRequests
                // and must be first in the other Access* packets
                // https://datatracker.ietf.org/doc/html/draft-ietf-radext-deprecating-radius/#section-5.2
                if (messageAuthenticatorPosition != 20 && !_skipBlastRadiusChecks)
                {
                    _logger.LogWarning("Message-Authenticator should be first attribute");
                }
            }

            return packet;
        }


        /// <summary>
        /// Parse bytes into packet with attributes
        /// Resizes packetBytes if needed
        /// </summary>
        private (RadiusPacket packet, int messageAuthenticatorPosition) ParsePacketBytes(
            ref byte[] packetBytes,
            byte[] sharedSecret)
        {
            var packetLength = BitConverter.ToUInt16(packetBytes.Skip(2).Take(2).Reverse().ToArray(), 0);
            if (packetBytes.Length < packetLength)
            {
                throw new ArgumentOutOfRangeException(nameof(packetBytes),
                    $"Packet length mismatch, expected: {packetLength}, actual: {packetBytes.Length}");
            }

            if (packetBytes.Length > packetLength)
            {
                Array.Resize(ref packetBytes, packetLength);
            }

            var packet = RadiusPacket.CreateFromCode((PacketCode)packetBytes[0]);
            packet.Authenticator = packetBytes[4..20];
            packet.Identifier = packetBytes[1];
            packet.Code = (PacketCode)packetBytes[0];

            var messageAuthenticatorPosition =
                AddAttributesToPacket(ref packet, packetBytes, packetLength, sharedSecret);

            return (packet, messageAuthenticatorPosition);
        }


        /// <summary>
        /// Get the raw packet bytes
        /// </summary>
        public byte[] GetBytes(IRadiusPacket packet, byte[] sharedSecret, byte[]? requestAuthenticator = null)
        {
            var (attributeBytes, messageAuthenticatorPosition) = GetAttributesBytes(packet, sharedSecret);
            var length = (ushort)(20 + attributeBytes.Length);

            // Max length is 4096 bytes...
            // https://datatracker.ietf.org/doc/html/rfc2865#section-3
            if (length > 4096)
            {
                throw new InvalidOperationException($"Packet length cannot exceed 4096, was {length}");
            }

            var packetBytes = new List<byte> { (byte)packet.Code, packet.Identifier }
                .Concat(BitConverter.GetBytes(length).Reverse()) // Populate packet length... Network byte order...
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
                    HandleRequestMessageAuthenticator(sharedSecret, messageAuthenticatorPosition, packetBytes);
                    Buffer.BlockCopy(Utils.CalculateRequestAuthenticator(sharedSecret, packetBytes),
                        0, packetBytes, 4, 16);
                    break;
                }
                case PacketCode.StatusServer:
                case PacketCode.AccessRequest:
                {
                    Buffer.BlockCopy(packet.Authenticator, 0, packetBytes, 4, 16);
                    HandleRequestMessageAuthenticator(sharedSecret, messageAuthenticatorPosition, packetBytes);
                    break;
                }
                case PacketCode.AccessAccept:
                case PacketCode.AccessReject:
                case PacketCode.AccessChallenge:
                case PacketCode.AccountingResponse:
                case PacketCode.StatusClient:
                case PacketCode.DisconnectAck:
                case PacketCode.DisconnectNak:
                case PacketCode.CoaAck:
                case PacketCode.CoaNak:
                default:
                {
                    if (requestAuthenticator == null)
                    {
                        throw new ArgumentNullException(nameof(requestAuthenticator),
                            "Request-Authenticator is required when creating response packets");
                    }

                    if (messageAuthenticatorPosition != 0)
                    {
                        var messageAuthenticator = Utils.CalculateResponseMessageAuthenticator(
                            packetBytes,
                            sharedSecret,
                            requestAuthenticator,
                            messageAuthenticatorPosition);

                        Buffer.BlockCopy(messageAuthenticator, 0, packetBytes, messageAuthenticatorPosition + 2, 16);
                    }

                    var authenticator = Utils.CalculateResponseAuthenticator(
                        sharedSecret,
                        requestAuthenticator,
                        packetBytes);

                    Buffer.BlockCopy(authenticator, 0, packetBytes, 4, 16);
                    break;
                }
            }

            return packetBytes;
        }


        /// <summary>
        /// Add a request message authenticator to the packet if applicable
        /// </summary>
        private static void HandleRequestMessageAuthenticator(
            byte[] sharedSecret,
            int messageAuthenticatorPosition,
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
        private (byte[] attributeBytes, int messageAuthenticatorPosition) GetAttributesBytes(IRadiusPacket packet,
            byte[] sharedSecret)
        {
            var messageAuthenticatorPosition = 0;
            var currentPosition = 20;

            var attributesBytes = packet.Attributes.SelectMany(a => a.Value.SelectMany(v =>
            {
                var contentBytes = Attribute.ToBytes(v);
                var headerBytes = new byte[2];

                switch (_dictionary.GetAttribute(a.Key))
                {
                    case DictionaryVendorAttribute vendorAttributeType:
                        headerBytes = new byte[8];
                        headerBytes[0] = 26; // VSA type

                        var vendorId = BitConverter.GetBytes(vendorAttributeType.VendorId).Reverse().ToArray();
                        Buffer.BlockCopy(vendorId, 0, headerBytes, 2, 4);
                        headerBytes[6] = (byte)vendorAttributeType.VendorCode;
                        headerBytes[7] = (byte)(2 + contentBytes.Length); // length of the vsa part
                        break;

                    case { } attributeType:
                        headerBytes[0] = attributeType.Code;

                        // Encrypt password if this is a User-Password attribute
                        if (attributeType.Code == 2)
                        {
                            contentBytes =
                                RadiusPassword.Encrypt(sharedSecret, packet.Authenticator, contentBytes);
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

                var attributeLength = headerBytes.Length + contentBytes.Length;

                if (attributeLength > byte.MaxValue)
                {
                    throw new InvalidOperationException($"Attribute max length is 255, was {attributeLength}");
                }

                headerBytes[1] = (byte)attributeLength;
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
        private int AddAttributesToPacket(ref RadiusPacket packet, byte[] packetBytes, int packetLength,
            byte[] sharedSecret)
        {
            var position = 20;
            var messageAuthenticatorPosition = 0;

            while (position < packetLength)
            {
                var typeCode = packetBytes[position];
                var attributeLength = packetBytes[position + 1];
                var attributeValueBytes = packetBytes[(position + 2)..(position + attributeLength)];

                try
                {
                    if (typeCode == 26) // VSA
                    {
                        var vsa = new VendorSpecificAttribute(attributeValueBytes);
                        var vsaType = _dictionary.GetVendorAttribute(vsa.VendorId, vsa.VendorCode);

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
                                        sharedSecret));
                            }
                            catch (Exception ex)
                            {
                                _logger.LogError(ex, "Something went wrong with vsa {name}", vsaType.Name);
                            }
                        }
                    }
                    else
                    {
                        var attributeType = _dictionary.GetAttribute(typeCode) ??
                                            throw new ArgumentNullException(nameof(typeCode));

                        // We need the location of the Message-Authenticator later to be able to zero it for validation
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
                                    sharedSecret));
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