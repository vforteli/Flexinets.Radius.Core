using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace Flexinets.Radius.Core.PacketTypes
{
    /// <summary>
    /// This class encapsulates a Radius packet and presents it in a more readable form
    /// </summary>
    public abstract class RadiusPacket : IRadiusPacket
    {
        public PacketCode Code { get; internal set; }
        public byte Identifier { get; internal set; }
        public byte[] Authenticator { get; internal set; } = new byte[16];
        public IDictionary<string, List<object>> Attributes { get; } = new Dictionary<string, List<object>>();


        internal static RadiusPacket CreateFromCode(PacketCode code) =>
            code switch
            {
                PacketCode.AccessRequest => new AccessRequest(),
                PacketCode.AccessAccept => new AccessAccept(),
                PacketCode.AccessReject => new AccessReject(),
                PacketCode.AccountingRequest => new AccountingRequest(),
                PacketCode.AccountingResponse => new AccountingResponse(),
                PacketCode.AccessChallenge => new AccessChallenge(),
                PacketCode.StatusServer => new StatusServer(),
                PacketCode.StatusClient => new StatusClient(),
                PacketCode.DisconnectRequest => new DisconnectRequest(),
                PacketCode.DisconnectAck => new DisconnectAck(),
                PacketCode.DisconnectNak => new DisconnectNak(),
                PacketCode.CoaRequest => new CoaRequest(),
                PacketCode.CoaAck => new CoaAck(),
                PacketCode.CoaNak => new CoaNak(),
                _ => throw new ArgumentOutOfRangeException()
            };


        protected RadiusPacket()
        {
        }


        protected RadiusPacket(PacketCode code, byte identifier)
        {
            Code = code;
            Identifier = identifier;
        }


        /// <summary>
        /// Gets a single attribute value with name cast to type
        /// Throws an exception if multiple attributes with the same name are found
        /// </summary>
        public T GetAttribute<T>(string name) => GetAttributes<T>(name).SingleOrDefault();


        /// <summary>
        /// Gets multiple attribute values with the same name cast to type
        /// </summary>
        public List<T> GetAttributes<T>(string name) =>
            Attributes.TryGetValue(name, out var attribute)
                ? attribute.Cast<T>().ToList()
                : new List<T>();


        public void AddAttribute(string name, string value) => AddAttributeObject(name, value);

        public void AddAttribute(string name, uint value) => AddAttributeObject(name, value);

        public void AddAttribute(string name, IPAddress value) => AddAttributeObject(name, value);

        public void AddAttribute(string name, byte[] value) => AddAttributeObject(name, value);

        /// <summary>
        /// Add a Message-Authenticator placeholder attribute to the packet
        /// The actual value is calculated when assembling the packet
        /// </summary>
        public void AddMessageAuthenticator() => AddAttribute("Message-Authenticator", new byte[16]);


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