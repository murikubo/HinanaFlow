import Foundation
import Network
import Security
import CryptoKit
import Darwin

public enum PeerPin {
    /// Both Apple and Windows hash the same SEC1 uncompressed P-256 point, not platform-specific encodings.
    public static func digest(key: SecKey) -> Data? {
        guard let attributes = SecKeyCopyAttributes(key) as? [String: Any],
              attributes[kSecAttrKeyType as String] as? String == kSecAttrKeyTypeECSECPrimeRandom as String,
              attributes[kSecAttrKeyClass as String] as? String == kSecAttrKeyClassPublic as String,
              attributes[kSecAttrKeySizeInBits as String] as? Int == 256,
              let encoded = SecKeyCopyExternalRepresentation(key, nil) as Data?,
              encoded.count == 65, encoded.first == 4 else { return nil }
        return Data(SHA256.hash(data: encoded))
    }
    public static func verifyCertificate(_ certificate: SecCertificate, pin: Data) -> Bool {
        var trust: SecTrust?
        guard pin.count == 32, SecTrustCreateWithCertificates(certificate,SecPolicyCreateBasicX509(),&trust) == errSecSuccess, let trust else { return false }
        return verify(trust,allowed:[pin])
    }
    static func verify(_ trust: SecTrust, allowed: Set<Data>) -> Bool {
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let cert = chain.first,
              let key = SecCertificateCopyKey(cert), let pin = digest(key: key), allowed.contains(pin) else { return false }
        // Explicit leaf validity checks also apply when a locally pinned certificate is a trust anchor.
        // Typed validity APIs avoid relying on display-oriented certificate property dictionaries.
        if #available(macOS 15.0, iOS 18.0, *) {
            guard let start = SecCertificateCopyNotValidBeforeDate(cert) as Date?,
                  let end = SecCertificateCopyNotValidAfterDate(cert) as Date?,
                  start <= Date(), Date() <= end else { return false }
        } else {
            // TODO: reviewed validity API for older OS versions; fail closed in the meantime.
            return false
        }
        guard SecTrustSetPolicies(trust, SecPolicyCreateBasicX509()) == errSecSuccess,
              SecTrustSetAnchorCertificates(trust, [cert] as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess else { return false }
        // Never allow AIA/OCSP network fetches in this local-first transport.
        guard SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess else { return false }
        return SecTrustEvaluateWithError(trust, nil)
    }
}

public enum LANAddress {
    /// Address filter only; current diagnostics additionally require a bound LANBinding.
    public static func permits(_ host: String) -> Bool {
        var v4 = in_addr()
        if inet_pton(AF_INET, host, &v4) == 1 {
            let n = UInt32(bigEndian: v4.s_addr)
            return n >> 24 == 10 || n >> 20 == 0xAC1 || n >> 16 == 0xC0A8 || n >> 16 == 0xA9FE
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, host, &v6) == 1 {
            return withUnsafeBytes(of: &v6) { b in
                (b[0] & 0xFE == 0xFC) || (b[0] == 0xFE && b[1] & 0xC0 == 0x80)
            }
        }
        return false
    }
}

public enum PinnedTLS {
    private static let queue = DispatchQueue(label: "dev.hinana.flow.tls")
    public static func validateApprovedPins(_ pins: Set<Data>) throws {
        guard !pins.isEmpty, pins.allSatisfy({ $0.count == 32 }) else { throw FlowError.untrusted }
    }
    static func options(pins: Set<Data>, identity: sec_identity_t?, audit:TLSHandshakeAudit? = nil, clientChallenge:Bool = false) throws -> NWParameters {
        try validateApprovedPins(pins)
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv13)
        sec_protocol_options_set_max_tls_protocol_version(tls.securityProtocolOptions, .TLSv13)
        sec_protocol_options_set_tls_resumption_enabled(tls.securityProtocolOptions, false)
        sec_protocol_options_set_tls_tickets_enabled(tls.securityProtocolOptions, false)
        sec_protocol_options_set_tls_renegotiation_enabled(tls.securityProtocolOptions, false)
        sec_protocol_options_set_peer_authentication_required(tls.securityProtocolOptions, true)
        if let identity {
            if clientChallenge {
                // Supply the client identity only in response to the server's CertificateRequest.
                sec_protocol_options_set_challenge_block(tls.securityProtocolOptions,{ _,complete in
                    audit?.recordLocalChallenge();complete(identity)
                },queue)
            } else {sec_protocol_options_set_local_identity(tls.securityProtocolOptions, identity)}
        }
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, peerTrust, complete in
            let trust = sec_trust_copy_ref(peerTrust).takeRetainedValue()
            let verified=PeerPin.verify(trust, allowed: pins)
            audit?.recordPeer(verified);complete(verified)
        }, queue)
        let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        parameters.includePeerToPeer = false
        parameters.prohibitedInterfaceTypes = [.cellular]
        return parameters
    }
    /// Caller supplies an OS-managed identity and an already approved public-key pin.
    /// This factory does not start networking or send application data.
    public static func connection(host: String, port: UInt16, pin: Data, identity: sec_identity_t) throws -> NWConnection {
        guard LANAddress.permits(host), port != 0 else { throw FlowError.invalidAddress }
        return NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!,
                            using: try options(pins: [pin], identity: identity))
    }
    public static func boundConnection(_ binding: LANBinding, pin: Data, identity: sec_identity_t) throws -> NWConnection {
        let parameters = try options(pins:[pin],identity:identity)
        parameters.requiredLocalEndpoint = .hostPort(host:.init(binding.local),port:.any)
        parameters.prohibitedInterfaceTypes = [.cellular, .loopback, .other]
        return NWConnection(host:.init(binding.peer),port:.init(rawValue:binding.port)!,using:parameters)
    }
    public static func boundListener(_ binding: LANBinding, pin: Data, identity: sec_identity_t) throws -> NWListener {
        let parameters = try options(pins:[pin],identity:identity)
        parameters.requiredLocalEndpoint = .hostPort(host:.init(binding.local),port:.init(rawValue:binding.port)!)
        parameters.prohibitedInterfaceTypes = [.cellular, .loopback, .other]
        return try NWListener(using:parameters)
    }
    public static func authenticatedConnection(_ binding:LANBinding,pin:Data,identity:sec_identity_t) throws -> (NWConnection,TLSHandshakeAudit) {
        let audit=TLSHandshakeAudit(server:false)
        let parameters=try options(pins:[pin],identity:identity,audit:audit,clientChallenge:true)
        parameters.requiredLocalEndpoint = .hostPort(host:.init(binding.local),port:.any)
        parameters.prohibitedInterfaceTypes = [.cellular,.loopback,.other]
        #if os(iOS)
        parameters.requiredInterfaceType = .wifi
        #endif
        return (NWConnection(host:.init(binding.peer),port:.init(rawValue:binding.port)!,using:parameters),audit)
    }
    public static func authenticatedListener(_ binding:LANBinding,pin:Data,identity:sec_identity_t) throws -> (NWListener,TLSHandshakeAudit) {
        let audit=TLSHandshakeAudit(server:true)
        let parameters=try options(pins:[pin],identity:identity,audit:audit)
        parameters.requiredLocalEndpoint = .hostPort(host:.init(binding.local),port:.init(rawValue:binding.port)!)
        parameters.prohibitedInterfaceTypes = [.cellular,.loopback,.other]
        #if os(iOS)
        parameters.requiredInterfaceType = .wifi
        #endif
        return (try NWListener(using:parameters),audit)
    }
    public static func bonjourListener(interface:NWInterface,pin:Data,identity:sec_identity_t) throws -> (NWListener,TLSHandshakeAudit) {
        guard [.wifi,.wiredEthernet].contains(interface.type) else {throw FlowError.invalidAddress}
        let audit=TLSHandshakeAudit(server:true)
        let parameters=try options(pins:[pin],identity:identity,audit:audit)
        parameters.requiredInterface=interface;parameters.prohibitedInterfaceTypes=[.cellular,.loopback,.other]
        return (try NWListener(using:parameters,on:.any),audit)
    }
    public static func bonjourConnection(endpoint:NWEndpoint,interface:NWInterface,pin:Data,identity:sec_identity_t) throws -> (NWConnection,TLSHandshakeAudit) {
        guard BonjourLAN.allowed(endpoint,on:interface),case .hostPort(_,let port)=endpoint,port.rawValue>=1024 else {throw FlowError.invalidAddress}
        let audit=TLSHandshakeAudit(server:false)
        let parameters=try options(pins:[pin],identity:identity,audit:audit,clientChallenge:true)
        parameters.requiredInterface=interface;parameters.prohibitedInterfaceTypes=[.cellular,.loopback,.other]
        return (NWConnection(to:endpoint,using:parameters),audit)
    }
    /// Legacy unbound factory, unused by the current authenticated manual-IP diagnostic.
    public static func listener(port: UInt16, pins: Set<Data>, identity: sec_identity_t) throws -> NWListener {
        guard port != 0 else { throw FlowError.invalidAddress }
        return try NWListener(using: options(pins: pins, identity: identity), on: NWEndpoint.Port(rawValue: port)!)
    }
}

/// A bounded handshake diagnostic. Closes on authentication, failure, cancellation or the fixed deadline.
/// Application bytes cannot be sent via this interface. UI wiring remains blocked.
public final class TLSProbe: @unchecked Sendable {
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "dev.hinana.flow.probe")
    private var finished = false // confined to queue
    public init(connection: NWConnection) { self.connection = connection }
    public func start(completion: @escaping @Sendable (Bool) -> Void) {
        queue.async { [self] in
            connection.stateUpdateHandler = { [self] state in
                switch state {
                case .ready: end(true, completion)
                case .failed, .cancelled: end(false, completion)
                default: break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + 10) { [self] in end(false, completion) }
        }
    }
    public func cancel() { queue.async { [self] in connection.cancel() } }
    private func end(_ success: Bool, _ completion: @Sendable (Bool) -> Void) {
        guard !finished else { return }
        finished = true; connection.stateUpdateHandler = nil; connection.cancel(); completion(success)
    }
}
