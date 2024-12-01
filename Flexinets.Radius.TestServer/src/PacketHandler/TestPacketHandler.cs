using Flexinets.Radius.Core;
using Flexinets.Radius.Core.PacketTypes;

namespace Flexinets.Radius;

/// <summary>
/// Demonstration of basic packet handler with a static username and password
/// </summary>
public class TestPacketHandler : IPacketHandler
{
    public async Task<IRadiusPacket?> HandlePacketAsync(IRadiusPacket packet)
    {
        await Task.CompletedTask.ConfigureAwait(false);
        
        switch (packet)
        {
            case AccountingRequest:
                return packet.GetAttribute<AcctStatusType>("Acct-Status-Type") switch
                {
                    AcctStatusType.Start => new AccountingResponse(packet.Identifier),
                    AcctStatusType.Stop => new AccountingResponse(packet.Identifier),
                    AcctStatusType.InterimUpdate => new AccountingResponse(packet.Identifier),
                    _ => throw new InvalidOperationException("Couldnt handle request?!"),
                };
            case AccessRequest:
            {
                var username = packet.GetAttribute<string>("User-Name");
                var password = packet.GetAttribute<string>("User-Password");

                if (username == "nemo" && password == "arctangent")
                {
                    var response = new AccessAccept(packet.Identifier);
                    response.AddMessageAuthenticator();
                    response.AddAttribute("Acct-Interim-Interval", 60);
                    return response;
                }

                var rejectPacket = new AccessReject(packet.Identifier);
                rejectPacket.AddMessageAuthenticator();
                return rejectPacket;
            }
            default:
                throw new InvalidOperationException("Couldnt handle request?!");
        }
    }


    /// <summary>
    /// Dispose
    /// </summary>
    public void Dispose()
    {
        GC.SuppressFinalize(this);
    }
}