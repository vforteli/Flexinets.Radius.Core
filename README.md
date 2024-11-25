# Radius packet parser and assembler library for .Net.

Includes Core functionality for parsing and assembling Radius packets using a dictionary

Conditionally compliant with RFCs  
https://tools.ietf.org/html/rfc2865  
https://tools.ietf.org/html/rfc2866  
https://tools.ietf.org/html/rfc5997

## Projects

### Flexinets.Radius.Core

Radius protocol bits and pieces. Published to NuGet here:
https://www.nuget.org/packages/Flexinets.Radius.Core/

### Flexinets.Radius.Core.Tests

Tests...

### Flexinets.Radius.TestClient

Contains a minimal client which can be used to send test packets

### Flexinets.Radius.TestServer

Contains a minimal server for responding with a static username and password with basic attributes

## BlastRadius support

To support communication with Radius servers or clients enforcing Blast Radius checks, a Message-Authenticator must be added to sent packets and validated when received.

```csharp
// Sending a packet
var requestPacket = new RadiusPacket(PacketCode.AccessRequest, 0, "xyzzy5461");
requestPacket.AddMessageAuthenticator(); // Add message authenticator for blast radius
requestPacket.AddAttribute("User-Name", "nemo");
requestPacket.AddAttribute("User-Password", "arctangent");
```

When receiving response packets, the request packet Authenticator must be passed to IRadiusPacketParse.Parse in order to calculate the correct Message-Authenticator in the response
When receiving request packets, the Message-Authenticator is required and validated by default for all Access\* packets in version 3.0.0 and greater.

In version 2.0.1 Blast radius checks can be enabled by setting skipBlastRadiusChecks to False when creating a RadiusPacketParser.

```csharp

/// Set skipBlastRadiusChecks when creating packet parser
var radiusPacketParser new RadiusPacketParser(
        loggerFactory.CreateLogger<RadiusPacketParser>(),
        RadiusDictionary.Parse(DefaultDictionary.RadiusDictionary),
        skipBlastRadiusChecks: false)   // Default 'false' in version >= 3.0.0 and 'true' in 2.0.1

/// ...

// Receiving a packet
var parsedPacket = radiusPacketParser.Parse(
                    reponsePacketBytes,
                    requestPacket.SharedSecret,
                    requestPacket.Authenticator); // <- corresponding request Authenticator
```
