import Foundation
import Network
import Darwin

public enum BonjourLAN {
    public static let serviceType="_hinanaflow._tcp"
    public static func validService(name:String,type:String,domain:String) -> Bool {
        !name.isEmpty && name.utf8.count<=63 && !name.unicodeScalars.contains(where:{$0.value==0}) &&
        (type.lowercased()==serviceType || type.lowercased()==serviceType+".") && domain.lowercased()=="local."
    }
    public static func label(_ name:String) -> String {
        let text=String(name.unicodeScalars.filter {
            switch $0.properties.generalCategory {case .control,.format,.lineSeparator,.paragraphSeparator:return false;default:return true}
        }.prefix(48))
        return text.isEmpty ? "이름 없는 서비스":text
    }
    public static func localHost(_ host:String) -> Bool {
        let h=host.lowercased()
        return h.utf8.count<=253 && h.hasSuffix(".local.") && !h.unicodeScalars.contains(where:{$0.value<=32 || $0.value==127})
    }
    public struct Address:Sendable,Equatable {
        public let text:String
        public let mask:Data
        public let index:UInt32
        public let bytes:Data
    }
    public static func addresses() -> [Address] {
        var first:UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&first)==0 else {return []};defer {freeifaddrs(first)}
        var item=first,result:[Address]=[]
        while let p=item {
            defer {item=p.pointee.ifa_next};let v=p.pointee
            guard v.ifa_flags & UInt32(IFF_UP) != 0,v.ifa_flags & UInt32(IFF_LOOPBACK|IFF_POINTOPOINT)==0,
                  let a=v.ifa_addr,let m=v.ifa_netmask else {continue}
            let name=String(cString:v.ifa_name)
            #if os(iOS)
            guard name=="en0" else {continue}
            #endif
            let family=Int32(a.pointee.sa_family)
            let bytes:Data,mask:Data
            if family==AF_INET {
                var address=UnsafeRawPointer(a).assumingMemoryBound(to:sockaddr_in.self).pointee.sin_addr
                var netmask=UnsafeRawPointer(m).assumingMemoryBound(to:sockaddr_in.self).pointee.sin_addr
                bytes=withUnsafeBytes(of:&address) {Data($0)};mask=withUnsafeBytes(of:&netmask) {Data($0)}
            } else if family==AF_INET6 {
                var address=UnsafeRawPointer(a).assumingMemoryBound(to:sockaddr_in6.self).pointee.sin6_addr
                var netmask=UnsafeRawPointer(m).assumingMemoryBound(to:sockaddr_in6.self).pointee.sin6_addr
                bytes=withUnsafeBytes(of:&address) {Data($0)};mask=withUnsafeBytes(of:&netmask) {Data($0)}
            } else {continue}
            let text=bytes.count==4 ? IPv4Address(bytes)?.debugDescription:IPv6Address(bytes)?.debugDescription
            if let text,LANAddress.permits(text) {result.append(Address(text:text,mask:mask,index:if_nametoindex(v.ifa_name),bytes:bytes))}
        }
        return result
    }
    /// Pure on-link check, independent of advertisements and keys. No DNS fallback.
    public static func onLink(local:Data,peer:Data,mask:Data) -> Bool {
        guard local.count==peer.count,mask.count==local.count,local != peer else {return false}
        if local.count==4,let a=IPv4Address(local),let b=IPv4Address(peer) {
            let m=mask.reduce(UInt32(0)) {($0<<8)|UInt32($1)}
            return LANBinding.sharesSubnet(local:a.debugDescription,peer:b.debugDescription,mask:m)
        }
        guard local.count==16,let a=IPv6Address(local),let b=IPv6Address(peer),!b.isIPv4Mapped,!b.isIPv4Compatabile,
              LANAddress.permits(a.debugDescription),LANAddress.permits(b.debugDescription) else {return false}
        if a.isLinkLocal && b.isLinkLocal {return true} // interface scope is separately mandatory
        guard local[0]&0xfe==0xfc,peer[0]&0xfe==0xfc else {return false}
        let bits:[Bool]=Array(mask).flatMap {byte in (0..<8).reversed().map {byte & (UInt8(1)<<$0) != 0}}
        let prefix=bits.prefix(while:{$0}).count
        guard (64...126).contains(prefix),!bits.dropFirst(prefix).contains(true) else {return false}
        return zip(zip(local,peer),mask).allSatisfy {pair,m in pair.0&m==pair.1&m}
    }
    public static func peerBytes(_ endpoint:NWEndpoint) -> Data? {
        guard case .hostPort(let host,_) = endpoint else {return nil}
        switch host {case .ipv4(let a):return a.rawValue;case .ipv6(let a):return a.rawValue;default:return nil}
    }
    public static func allowed(_ endpoint:NWEndpoint,on interface:NWInterface) -> Bool {
        guard [.wifi,.wiredEthernet].contains(interface.type),let peer=peerBytes(endpoint) else {return false}
        #if os(iOS)
        guard interface.type == .wifi,interface.name=="en0" else {return false}
        #endif
        let local=addresses().filter {$0.index==UInt32(interface.index)}
        guard !local.contains(where:{$0.bytes==peer}) else {return false}
        return local.contains {onLink(local:$0.bytes,peer:peer,mask:$0.mask)}
    }
    public static func pathSignature(_ interfaces:[NWInterface]) -> Set<String> {
        let indexes=Set(interfaces.filter {[.wifi,.wiredEthernet].contains($0.type)}.map {UInt32($0.index)})
        return Set(addresses().filter {indexes.contains($0.index)}.map {String($0.index)+":"+$0.text+":"+$0.mask.base64EncodedString()})
    }
}

/// A session-local discovery catalogue, deliberately containing no key/trust information.
public struct BonjourCatalog:Sendable {
    public struct Advertisement:Hashable,Sendable {
        public let name:String
        public let type:String
        public let domain:String
        public let interfaceIndex:UInt32
        public init(name:String,type:String,domain:String,interfaceIndex:UInt32) {self.name=name;self.type=type;self.domain=domain;self.interfaceIndex=interfaceIndex}
        public static func ==(a:Self,b:Self)->Bool {a.name.utf8.elementsEqual(b.name.utf8) && a.type==b.type && a.domain==b.domain && a.interfaceIndex==b.interfaceIndex}
        public func hash(into hasher:inout Hasher) {hasher.combine(Data(name.utf8));hasher.combine(type);hasher.combine(domain);hasher.combine(interfaceIndex)}
    }
    public struct Entry:Sendable {public let id:UUID;public let advertisement:Advertisement}
    public private(set) var entries:[Entry]=[]
    public init() {}
    public mutating func replace(_ advertisements:[Advertisement]) {
        var next:[Entry]=[],seen=Set<Advertisement>()
        for a in advertisements.prefix(256) where next.count<64 {
            guard a.interfaceIndex>0,BonjourLAN.validService(name:a.name,type:a.type,domain:a.domain),seen.insert(a).inserted else {continue}
            next.append(Entry(id:entries.first(where:{$0.advertisement==a})?.id ?? UUID(),advertisement:a))
        }
        entries=next
    }
    public mutating func clear() {entries=[]}
}
