using System.Collections.Generic;
using System.Net;

namespace Flexinets.Radius.Core
{
    public interface IRadiusPacket
    {
        byte Identifier
        {
            get;
        }
        byte[] Authenticator
        {
            get;
        }
        byte[] SharedSecret
        {
            get;
        }
        PacketCode Code
        {
            get;
        }
        byte[] RequestAuthenticator
        {
            get;
        }
        IRadiusPacket CreateResponsePacket(PacketCode responseCode);

        T GetAttribute<T>(string name);

        List<T> GetAttributes<T>(string name);

        void AddAttribute(string name, string value);
        void AddAttribute(string name, uint value);
        void AddAttribute(string name, IPAddress value);
        void AddAttribute(string name, byte[] value);

        IDictionary<string, List<object>> Attributes
        {
            get;
        }
    }
}
