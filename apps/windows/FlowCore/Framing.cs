using System.Buffers.Binary;
namespace HinanaFlow.Core;

// Legacy bulk/file and in-band pairing gate. Desktop OOB text is authorized by TextProtocol.
public static class TransferGate
{
    public const bool PairingEnabled = false;
    public static bool Authorize(bool trusted, bool userApproved) => false;
}

public sealed class ControlDecoder
{
    private readonly byte[] header = new byte[5];
    private int headerCount;
    private byte[]? body;
    private int bodyCount;
    public List<byte[]> Feed(ReadOnlySpan<byte> input)
    {
        var frames = new List<byte[]>();
        foreach (byte b in input)
        {
            if (body is null)
            {
                header[headerCount++] = b;
                if (headerCount == 5)
                {
                    uint n = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(1));
                    if (header[0] != 1 || n is 0 or > 65536) throw new InvalidDataException("invalid_frame");
                    body = new byte[(int)n];
                }
            }
            else
            {
                body[bodyCount++] = b;
                if (bodyCount == body.Length)
                {
                    frames.Add(body); body = null; bodyCount = 0; headerCount = 0;
                }
            }
        }
        return frames;
    }
    public void Finish()
    {
        if (headerCount != 0 || body is not null) throw new InvalidDataException("incomplete_frame");
    }
    public static byte[] Encode(ReadOnlySpan<byte> payload)
    {
        if (payload.Length is 0 or > 65536) throw new InvalidDataException("invalid_frame");
        byte[] result = new byte[5 + payload.Length]; result[0] = 1;
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(1), (uint)payload.Length);
        payload.CopyTo(result.AsSpan(5)); return result;
    }
    // One fixed deadline for the entire frame, never reset by slow input.
    public static async Task<byte[]> ReadAsync(Stream stream, CancellationToken cancellation)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        byte[] header = new byte[5];
        await stream.ReadExactlyAsync(header, deadline.Token);
        uint n = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(1));
        if (header[0] != 1 || n is 0 or > 65536) throw new InvalidDataException("invalid_frame");
        byte[] body = new byte[(int)n];
        await stream.ReadExactlyAsync(body, deadline.Token); return body;
    }
}
