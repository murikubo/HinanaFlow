import Foundation
import Security

@MainActor public protocol AppleIdentityStore {
    func loadOrCreate() throws -> SecIdentity
    func trustedPeer(localPin:Data) throws -> Data?
    func confirm(localPin:Data,peerPin:Data,oobConfirmed:Bool,mutualTLS:Bool) throws
    func forgetPeer() throws
}
public enum IdentityPin {
    public static func digest(of identity:SecIdentity) throws -> Data {
        var cert:SecCertificate?
        guard SecIdentityCopyCertificate(identity,&cert)==errSecSuccess,let cert,
              let key=SecCertificateCopyKey(cert),let pin=PeerPin.digest(key:key) else {throw IdentityError.invalidIdentity}
        return pin
    }
}
@MainActor public enum PlatformIdentityStore {
    public static func make(profile:ValidationProfile = .production) -> any AppleIdentityStore {
        return IOSIdentityStore(profile:profile)
    }
}

/// Security.framework may return numeric attributes as NSNumber even when the
/// public constant is a numeric CFString. Accept only the exact EC identifier.
public enum KeyAttributeValue {
    public static func isECPrimeRandom(_ value:Any?) -> Bool {
        if let value=value as? String {return value == kSecAttrKeyTypeECSECPrimeRandom as String}
        if let value=value as? NSNumber,CFGetTypeID(value) != CFBooleanGetTypeID() {
            return value.stringValue == kSecAttrKeyTypeECSECPrimeRandom as String
        }
        return false
    }
}
