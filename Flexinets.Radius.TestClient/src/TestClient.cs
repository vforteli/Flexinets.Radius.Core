using Flexinets.Radius.Core;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace Flexinets.Radius;

public record PendingRequest(byte Identifier, IPEndPoint RemoteEndpoint);

/// <summary>
/// Create a radius client which sends and receives responses on localEndpoint
/// </summary>
public class RadiusClient(IPEndPoint localEndpoint, IRadiusPacketParser radiusPacketParser) : IDisposable
{
    private readonly UdpClient _udpClient = new(localEndpoint);
    private Task? _receiveLoopTask;
    private readonly CancellationTokenSource _cancellationTokenSource = new();

    private readonly ConcurrentDictionary<PendingRequest, TaskCompletionSource<UdpReceiveResult>> _pendingRequests =
        new();


    /// <summary>
    /// Send a packet with default timeout of 3 seconds
    /// </summary>
    public async Task<IRadiusPacket> SendPacketAsync(IRadiusPacket requestPacket, IPEndPoint remoteEndpoint) =>
        await SendPacketAsync(requestPacket, remoteEndpoint, TimeSpan.FromSeconds(3));


    /// <summary>
    /// Send a packet with specified timeout
    /// </summary>
    public async Task<IRadiusPacket> SendPacketAsync(
        IRadiusPacket requestPacket,
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
        if (_pendingRequests.TryAdd(new PendingRequest(requestPacket.Identifier, remoteEndpoint), completionSource))
        {
            var requestPacketBytes = radiusPacketParser.GetBytes(requestPacket);
            await _udpClient.SendAsync(requestPacketBytes, requestPacketBytes.Length, remoteEndpoint);
            var completedTask = await Task.WhenAny(completionSource.Task, Task.Delay(timeout));
            if (completedTask == completionSource.Task)
            {
                return radiusPacketParser.Parse(
                    completionSource.Task.Result.Buffer,
                    requestPacket.SharedSecret ?? throw new ArgumentNullException(nameof(requestPacket.SharedSecret)),
                    requestPacket.Authenticator);
            }

            if (_pendingRequests.TryRemove(new PendingRequest(requestPacket.Identifier, remoteEndpoint), out var tcs))
            {
                tcs.SetCanceled();
            }

            throw new InvalidOperationException(
                $"Receive response for id {requestPacket.Identifier} timed out after {timeout}");
        }

        throw new InvalidOperationException($"There is already a pending receive with id {requestPacket.Identifier}");
    }


    /// <summary>
    /// Receive packets in a loop and complete tasks based on identifier
    /// </summary>
    private async Task StartReceiveLoopAsync()
    {
        while (true)
        {
            try
            {
                var response = await _udpClient.ReceiveAsync();
                if (_pendingRequests.TryRemove(
                        new PendingRequest(response.Buffer[1], response.RemoteEndPoint),
                        out var tcs))
                {
                    tcs.SetResult(response);
                }
            }
            catch (ObjectDisposedException)
            {
                // This is thrown when udpclient is disposed, can be safely ignored
                return;
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