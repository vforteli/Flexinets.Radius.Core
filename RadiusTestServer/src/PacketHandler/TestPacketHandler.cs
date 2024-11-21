using Flexinets.Radius.Core;

namespace Flexinets.Radius;

/// <summary>
/// Demonstration of basic packet handler with a static username and password
/// </summary>
public class TestPacketHandler : IPacketHandler
{
    public IRadiusPacket HandlePacket(IRadiusPacket packet)
    {
        if (packet.Code == PacketCode.AccountingRequest)
        {
            var acctStatusType = packet.GetAttribute<AcctStatusType>("Acct-Status-Type");
            if (acctStatusType == AcctStatusType.Start)
            {
                return packet.CreateResponsePacket(PacketCode.AccountingResponse);
            }

            if (acctStatusType == AcctStatusType.Stop)
            {
                return packet.CreateResponsePacket(PacketCode.AccountingResponse);
            }

            if (acctStatusType == AcctStatusType.InterimUpdate)
            {
                return packet.CreateResponsePacket(PacketCode.AccountingResponse);
            }
        }
        else if (packet.Code == PacketCode.AccessRequest)
        {
            if (packet.GetAttribute<string>("User-Name") == "user@example.com" &&
                packet.GetAttribute<string>("User-Password") == "1234")
            {
                var response = packet.CreateResponsePacket(PacketCode.AccessAccept);
                response.AddAttribute("Acct-Interim-Interval", 60);
                return response;
            }

            return packet.CreateResponsePacket(PacketCode.AccessReject);
        }

        throw new InvalidOperationException("Couldnt handle request?!");
    }


    /// <summary>
    /// Dispose
    /// </summary>
    public void Dispose()
    {
    }
}