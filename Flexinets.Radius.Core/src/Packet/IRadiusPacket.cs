using System.Collections.Generic;
using System.Net;

namespace Flexinets.Radius.Core
{
    public interface IRadiusPacket
    {
        byte Identifier { get; }
        byte[] Authenticator { get; }
        byte[] SharedSecret { get; }
        PacketCode Code { get; }
        byte[] RequestAuthenticator { get; }
        IRadiusPacket CreateResponsePacket(PacketCode responseCode);

        T GetAttribute<T>(string name);

        List<T> GetAttributes<T>(string name);

        void AddAttribute(string name, string value);
        void AddAttribute(string name, uint value);
        void AddAttribute(string name, IPAddress value);
        void AddAttribute(string name, byte[] value);

        /// <summary>
        /// Add a Message-Authenticator placeholder attribute to the packet
        /// The actual value is calculated when assembling the packet
        /// </summary>
        void AddMessageAuthenticator();

        IDictionary<string, List<object>> Attributes { get; }
    }
}