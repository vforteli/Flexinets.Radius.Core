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
            return packet.GetAttribute<AcctStatusType>("Acct-Status-Type") switch
            {
                AcctStatusType.Start => packet.CreateResponsePacket(PacketCode.AccountingResponse),
                AcctStatusType.Stop => packet.CreateResponsePacket(PacketCode.AccountingResponse),
                AcctStatusType.InterimUpdate => packet.CreateResponsePacket(PacketCode.AccountingResponse),
                _ => throw new InvalidOperationException("Couldnt handle request?!"),
            };
        }

        if (packet.Code == PacketCode.AccessRequest)
        {
            var username = packet.GetAttribute<string>("User-Name");
            var password = packet.GetAttribute<string>("User-Password");

            if (username == "nemo" && password == "arctangent")
            {
                var response = packet.CreateResponsePacket(PacketCode.AccessAccept);
                response.AddMessageAuthenticator();
                response.AddAttribute("Acct-Interim-Interval", 60);
                return response;
            }

            var rejectPacket = packet.CreateResponsePacket(PacketCode.AccessReject);
            rejectPacket.AddMessageAuthenticator();
            return rejectPacket;
        }

        throw new InvalidOperationException("Couldnt handle request?!");
    }


    /// <summary>
    /// Dispose
    /// </summary>
    public void Dispose()
    {
        GC.SuppressFinalize(this);
    }
}