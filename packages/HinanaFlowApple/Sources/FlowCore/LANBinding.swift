import Foundation
import Darwin
import Network

public struct LANInterface: Sendable { public let address: String; public let mask: UInt32; public let name: String }
public struct LANBinding: Sendable {
    public let local: String
    public let peer: String
    public let port: UInt16
    public static func peerMatches(_ endpoint:NWEndpoint,expected:String) -> Bool {
        guard case .hostPort(let host,_) = endpoint,case .ipv4(let actual) = host,
              let expectedAddress=IPv4Address(expected) else {return false}
        return actual.rawValue==expectedAddress.rawValue
    }
    private static func number(_ text: String) -> UInt32? {
        var value = in_addr(); guard inet_pton(AF_INET, text, &value) == 1 else { return nil }
        return UInt32(bigEndian:value.s_addr)
    }
    public static func sharesSubnet(local: String, peer: String, mask: UInt32) -> Bool {
        guard let a = number(local), let b = number(peer), LANAddress.permits(local), LANAddress.permits(peer), a != b else { return false }
        let count = mask.nonzeroBitCount
        guard (16...30).contains(count), mask == UInt32.max << (32-count) else { return false }
        let suffix = b & ~mask
        return a & mask == b & mask && suffix != 0 && suffix != ~mask
    }
    public static func interfaces() -> [LANInterface] {
        var first: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&first) == 0 else { return [] }; defer { freeifaddrs(first) }
        var item = first; var result: [LANInterface] = []
        while let current = item {
            defer { item = current.pointee.ifa_next }
            let x = current.pointee
            #if os(iOS)
            // This first real-device profile supports iPhone Wi-Fi (en0) only, never cellular/tunnels.
            guard String(cString:x.ifa_name)=="en0" else {continue}
            #endif
            guard x.ifa_flags & UInt32(IFF_UP) != 0, x.ifa_flags & UInt32(IFF_LOOPBACK | IFF_POINTOPOINT) == 0,
                  let addr = x.ifa_addr, addr.pointee.sa_family == UInt8(AF_INET), let mask = x.ifa_netmask else { continue }
            let ip = UnsafeRawPointer(addr).assumingMemoryBound(to:sockaddr_in.self).pointee.sin_addr
            let netmask = UnsafeRawPointer(mask).assumingMemoryBound(to:sockaddr_in.self).pointee.sin_addr
            var mutable = ip; var buffer = [CChar](repeating:0,count:Int(INET_ADDRSTRLEN))
            guard inet_ntop(AF_INET,&mutable,&buffer,socklen_t(buffer.count)) != nil else { continue }
            let text = buffer.withUnsafeBufferPointer { String(cString:$0.baseAddress!) }
            if LANAddress.permits(text) { result.append(LANInterface(address:text, mask:UInt32(bigEndian:netmask.s_addr),name:String(cString:x.ifa_name))) }
        }
        return result
    }
    public init(local: String, peer: String, port: UInt16) throws {
        guard port >= 1024, let selected = Self.interfaces().first(where: { $0.address == local }),
              Self.sharesSubnet(local:local,peer:peer,mask:selected.mask) else { throw FlowError.invalidAddress }
        self.local=local; self.peer=peer; self.port=port
    }
}
