using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
namespace HinanaFlow.Core;
public sealed record LanBinding(IPAddress Local, IPAddress Peer, int Port)
{
    public static bool SharesSubnet(IPAddress local, IPAddress peer, IPAddress netmask)
    {
        var a=local.GetAddressBytes(); var b=peer.GetAddressBytes(); var m=netmask.GetAddressBytes();
        if (a.Length!=4 || b.Length!=4 || m.Length!=4 || !LanAddress.Permits(local) || !LanAddress.Permits(peer) || local.Equals(peer)) return false;
        uint mask=System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(m);
        int prefix=System.Numerics.BitOperations.PopCount(mask);
        if (prefix is <16 or >30 || mask != uint.MaxValue << (32-prefix)) return false;
        uint aa=System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(a), bb=System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(b);
        return (aa & mask)==(bb & mask) && (bb & ~mask)!=0 && (bb & ~mask)!=~mask;
    }
    public static string[] Addresses() => Interfaces().Select(x=>x.Address.ToString()).Distinct().ToArray();
    private static IEnumerable<UnicastIPAddressInformation> Interfaces() => NetworkInterface.GetAllNetworkInterfaces()
        .Where(n=>n.OperationalStatus==OperationalStatus.Up && n.NetworkInterfaceType is NetworkInterfaceType.Ethernet or NetworkInterfaceType.Wireless80211)
        .SelectMany(n=>n.GetIPProperties().UnicastAddresses).Where(x=>x.Address.AddressFamily==AddressFamily.InterNetwork && LanAddress.Permits(x.Address));
    public void Validate()
    {
        if (Port is <1024 or >65535 || !Interfaces().Any(x=>x.Address.Equals(Local) && SharesSubnet(Local,Peer,x.IPv4Mask)))
            throw new InvalidDataException("lan_binding");
    }
}
