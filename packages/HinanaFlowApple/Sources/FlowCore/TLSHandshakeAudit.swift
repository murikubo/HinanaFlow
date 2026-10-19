import Foundation
import Network
import Security

/// Callback state is protected by a lock. The audit is never reused across sessions.
public final class TLSHandshakeAudit:@unchecked Sendable {
    private let lock=NSLock()
    private var peerVerified=false
    private var localPresented=false
    init(server:Bool) {localPresented=server} // Server's configured identity is mandatory for native TLS .ready.
    func recordPeer(_ verified:Bool) {lock.lock();peerVerified=verified;lock.unlock()}
    func recordLocalChallenge() {lock.lock();localPresented=true;lock.unlock()}
    public func evidence(for connection:NWConnection) throws -> TLSPeerEvidence {
        guard let tls=connection.metadata(definition:NWProtocolTLS.definition) as? NWProtocolTLS.Metadata else {throw FlowError.untrusted}
        let metadata=tls.securityProtocolMetadata
        var peerPin:Data?;var visitedLeaf=false
        let accessible=sec_protocol_metadata_access_peer_certificate_chain(metadata) { certificate in
            guard !visitedLeaf else {return};visitedLeaf=true
            let cert=sec_certificate_copy_ref(certificate).takeRetainedValue()
            if let key=SecCertificateCopyKey(cert) {peerPin=PeerPin.digest(key:key)}
        }
        guard accessible,let peerPin else {throw FlowError.untrusted}
        lock.lock();let peer=peerVerified;let local=localPresented;lock.unlock()
        return TLSPeerEvidence(peerPin:peerPin,
            tls13:sec_protocol_metadata_get_negotiated_tls_protocol_version(metadata) == .TLSv13 && !sec_protocol_metadata_get_early_data_accepted(metadata),
            peerCertificateVerified:peer,localIdentityPresented:local)
    }
}
