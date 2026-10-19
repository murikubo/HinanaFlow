import Foundation
import Network
import dnssd
import Darwin
import FlowCore

private final class ResolverContext:@unchecked Sendable {weak var owner:LocalServiceResolver?}
/// This resource holder moves cleanup to the callback queue even if the last owner is released elsewhere.
private final class ResolverResources:@unchecked Sendable {
    let context=ResolverContext()
    var service:DNSServiceRef?
    var addresses:DNSServiceRef?
    func close() {
        dispatchPrecondition(condition:.onQueue(.main))
        context.owner=nil
        if let ref=service {DNSServiceRefDeallocate(ref)};service=nil
        if let ref=addresses {DNSServiceRefDeallocate(ref)};addresses=nil
    }
}
/// Main-queue operations/callbacks, weak context ownership, queue-confined native ref cleanup.
final class LocalServiceResolver:@unchecked Sendable {
    private var resources:ResolverResources?
    private var service:DNSServiceRef? {get {resources?.service} set {resources?.service=newValue}}
    private var addresses:DNSServiceRef? {get {resources?.addresses} set {resources?.addresses=newValue}}
    private var deadline:DispatchWorkItem?
    private var completion:((NWEndpoint?)->Void)?
    private var interface:NWInterface?
    private var port:UInt16=0
    private var candidates:[NWEndpoint]=[]
    func start(name:String,type:String,domain:String,interface:NWInterface,completion:@escaping (NWEndpoint?)->Void) {
        dispatchPrecondition(condition:.onQueue(.main));cancel()
        guard BonjourLAN.validService(name:name,type:type,domain:domain) else {completion(nil);return}
        self.interface=interface;self.completion=completion
        let resources=ResolverResources();resources.context.owner=self;self.resources=resources
        let context=Unmanaged.passUnretained(resources.context).toOpaque()
        let error=DNSServiceResolve(&service,DNSServiceFlags(kDNSServiceFlagsForceMulticast),UInt32(interface.index),name,type,domain,{_,_,index,error,_,host,port,_,_,context in
            guard let context else {return}
            guard let resolver=Unmanaged<ResolverContext>.fromOpaque(context).takeUnretainedValue().owner else {return}
            guard error==0,let host,let interface=resolver.interface,index==UInt32(interface.index),
                  BonjourLAN.localHost(String(cString:host)),UInt16(bigEndian:port)>=1024 else {resolver.finish(nil);return}
            resolver.port=UInt16(bigEndian:port)
            guard resolver.addresses==nil else {return}
            let status=DNSServiceGetAddrInfo(&resolver.addresses,DNSServiceFlags(kDNSServiceFlagsForceMulticast),index,
                DNSServiceProtocol(kDNSServiceProtocol_IPv4|kDNSServiceProtocol_IPv6),host,{_,flags,index,error,_,address,_,context in
                guard let context else {return}
                guard let r=Unmanaged<ResolverContext>.fromOpaque(context).takeUnretainedValue().owner else {return}
                guard error==0,let address,let interface=r.interface,index==UInt32(interface.index) else {return}
                let endpoint:NWEndpoint?
                if address.pointee.sa_family==UInt8(AF_INET) {
                    var a=UnsafeRawPointer(address).assumingMemoryBound(to:sockaddr_in.self).pointee.sin_addr
                    endpoint=withUnsafeBytes(of:&a) {IPv4Address(Data($0),interface).map { .hostPort(host:.ipv4($0),port:.init(rawValue:r.port)!)} }
                } else if address.pointee.sa_family==UInt8(AF_INET6) {
                    var a=UnsafeRawPointer(address).assumingMemoryBound(to:sockaddr_in6.self).pointee.sin6_addr
                    endpoint=withUnsafeBytes(of:&a) {IPv6Address(Data($0),interface).map { .hostPort(host:.ipv6($0),port:.init(rawValue:r.port)!)} }
                } else {endpoint=nil}
                if let endpoint,BonjourLAN.allowed(endpoint,on:interface) {
                    if flags & DNSServiceFlags(kDNSServiceFlagsAdd) != 0 {if !r.candidates.contains(endpoint),r.candidates.count<16 {r.candidates.append(endpoint)}}
                    else {r.candidates.removeAll {$0==endpoint}}
                }
                // Prefer IPv4 if present; IPv6 stays available on IPv6-only LANs.
                if flags & DNSServiceFlags(kDNSServiceFlagsMoreComing)==0,!r.candidates.isEmpty {
                    let chosen=r.candidates.first {BonjourLAN.peerBytes($0)?.count==4} ?? r.candidates[0]
                    r.finish(chosen)
                }
            },context)
            if status != 0 {resolver.finish(nil)}
            else if let ref=resolver.addresses,DNSServiceSetDispatchQueue(ref,.main) != 0 {resolver.finish(nil)}
        },context)
        guard error==0,let service else {finish(nil);return}
        guard DNSServiceSetDispatchQueue(service,.main)==0 else {finish(nil);return}
        let timeout=DispatchWorkItem {[weak self] in self?.finish(nil)};deadline=timeout
        DispatchQueue.main.asyncAfter(deadline:.now()+5,execute:timeout)
    }
    private func finish(_ endpoint:NWEndpoint?) {
        let callback=completion;completion=nil;cancel();callback?(endpoint)
    }
    func cancel() {
        dispatchPrecondition(condition:.onQueue(.main))
        deadline?.cancel();deadline=nil;completion=nil
        let old=resources;resources=nil;old?.close()
        interface=nil;candidates=[]
    }
    deinit {
        deadline?.cancel()
        if let resources {DispatchQueue.main.async {resources.close()}}
    }
}
