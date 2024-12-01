using Flexinets.Radius.Core;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace Flexinets.Radius;

/// <summary>
/// Create a radius client which sends and receives responses on localEndpoint
/// </summary>
public class RadiusClient(IPEndPoint localEndpoint, IRadiusPacketParser radiusPacketParser) : IDisposable
{
    private record PendingRequest(byte Identifier, IPEndPoint RemoteEndpoint);

    private readonly UdpClient _udpClient = new(localEndpoint);
    private Task? _receiveLoopTask;
    private readonly CancellationTokenSource _cancellationTokenSource = new();

    private readonly ConcurrentDictionary<PendingRequest, TaskCompletionSource<UdpReceiveResult>> _pendingRequests =
        new();


    /// <summary>
    /// Send a packet and wait for response with default timeout of 3 seconds
    /// </summary>
    public async Task<IRadiusPacket> SendPacketAsync(
        IRadiusPacket packet,
        byte[] sharedSecret,
        IPEndPoint remoteEndpoint) =>
        await SendPacketAsync(packet, sharedSecret, remoteEndpoint, TimeSpan.FromSeconds(3));


    /// <summary>
    /// Send a packet and wait for response with specified timeout
    /// </summary>
    public async Task<IRadiusPacket> SendPacketAsync(
        IRadiusPacket packet,
        byte[] sharedSecret,
        IPEndPoint remoteEndpoint,
        TimeSpan timeout)
    {
        // Start a receive loop before sending packet if one isnt already running to ensure we can receive the response
        _receiveLoopTask ??= Task.Factory.StartNew(
            StartReceiveLoopAsync,
            _cancellationTokenSource.Token,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default);

        var completionSource = new TaskCompletionSource<UdpReceiveResult>();
        var pendingRequest = new PendingRequest(packet.Identifier, remoteEndpoint);

        if (!_pendingRequests.TryAdd(pendingRequest, completionSource))
        {
            throw new InvalidOperationException($"There is already a pending receive with id {packet.Identifier}");
        }

        await _udpClient.SendAsync(radiusPacketParser.GetBytes(packet, sharedSecret), remoteEndpoint)
            .ConfigureAwait(false);

        if (await Task.WhenAny(completionSource.Task, Task.Delay(timeout)).ConfigureAwait(false) ==
            completionSource.Task)
        {
            return radiusPacketParser.Parse(
                completionSource.Task.Result.Buffer,
                sharedSecret,
                packet.Authenticator);
        }

        if (_pendingRequests.TryRemove(pendingRequest, out var tcs))
        {
            tcs.SetCanceled();
        }

        throw new TimeoutException($"Receive response for id {packet.Identifier} timed out after {timeout}");
    }

    /// <summary>
    /// Receive packets in a loop and complete tasks based on identifier
    /// </summary>
    private async Task StartReceiveLoopAsync()
    {
        while (!_cancellationTokenSource.IsCancellationRequested)
        {
            try
            {
                var response = await _udpClient.ReceiveAsync(_cancellationTokenSource.Token).ConfigureAwait(false);
                if (_pendingRequests.TryRemove(
                        new PendingRequest(response.Buffer[1], response.RemoteEndPoint),
                        out var tcs))
                {
                    tcs.SetResult(response);
                }
            }
            catch (ObjectDisposedException) // This is thrown when udpclient is disposed, can be safely ignored
            {
            }
        }
    }


    /// <summary>
    /// Dispose
    /// </summary>
    public void Dispose()
    {
        GC.SuppressFinalize(this);
        _cancellationTokenSource.Cancel();
        _receiveLoopTask?.Dispose();
        _udpClient.Dispose();
    }
}