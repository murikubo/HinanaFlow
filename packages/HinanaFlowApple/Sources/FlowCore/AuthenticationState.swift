import Foundation

/// Pure, shared authorization state. The Network adapter supplies evidence only after native TLS .ready.
public struct TLSPeerEvidence:Sendable {
    public let peerPin:Data
    public let tls13:Bool
    public let peerCertificateVerified:Bool
    public let localIdentityPresented:Bool
    public init(peerPin:Data,tls13:Bool,peerCertificateVerified:Bool,localIdentityPresented:Bool) {
        self.peerPin=peerPin;self.tls13=tls13
        self.peerCertificateVerified=peerCertificateVerified;self.localIdentityPresented=localIdentityPresented
    }
}
public struct AuthenticationState:Sendable {
    public enum Phase:Sendable {case stopped,handshaking,verified,ready,closed}
    public private(set) var phase:Phase = .stopped
    public private(set) var active=false
    private var expected=Data()
    public var maySendApplicationData:Bool {active && phase == .ready}
    public init() {}
    public mutating func setActive(_ active:Bool) {
        self.active=active
        if !active {close()}
    }
    public mutating func begin(localPin:Data,expectedPeer:Data,storedPeer:Data?,oobConfirmed:Bool) throws {
        guard active,(phase == .stopped || phase == .closed),localPin.count==32,expectedPeer.count==32,localPin != expectedPeer
        else {close();throw FlowError.untrusted}
        if let storedPeer {
            guard storedPeer.count==32,storedPeer==expectedPeer else {close();throw IdentityError.keyChanged}
        } else if !oobConfirmed {close();throw IdentityError.oobRequired}
        expected=expectedPeer;phase = .handshaking
    }
    public mutating func nativeTLSReady(_ evidence:TLSPeerEvidence) throws {
        guard active,phase == .handshaking,evidence.tls13,evidence.peerCertificateVerified,
              evidence.localIdentityPresented,evidence.peerPin==expected
        else {close();throw FlowError.untrusted}
        phase = .verified
    }
    public mutating func trustPersisted() throws {
        guard active,phase == .verified else {close();throw FlowError.untrusted}
        phase = .ready
    }
    public func requireApplicationData() throws {
        guard maySendApplicationData else {throw FlowError.untrusted}
    }
    public mutating func close() {phase = .closed;expected=Data()}
}
