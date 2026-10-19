#if os(macOS)
import Foundation
import Security

@MainActor public final class MacIdentityStore: AppleIdentityStore {
    // Legacy software store remains fail-closed; current Apple apps use Secure Enclave.
    private let label = "dev.hinana.flow.identity.v1"
    private let service = "dev.hinana.flow.trust.v1"
    public init() {}
    private func check(_ status: OSStatus) throws { guard status == errSecSuccess else { throw IdentityError.store(status) } }
    /// Uses the macOS local file-based Keychain (OS lock/ACL; no iCloud synchronization or entitlement dependency).
    /// Only invoked by the app's explicit identity action, never by build/tests.
    public func loadOrCreate() throws -> SecIdentity {
        if let existing = try load() { return existing }
        let tag = Data(label.utf8)
        var reference: CFTypeRef?
        let query: [CFString: Any] = [kSecClass:kSecClassKey, kSecAttrApplicationTag:tag,
            kSecAttrKeyClass:kSecAttrKeyClassPrivate, kSecAttrKeyType:kSecAttrKeyTypeECSECPrimeRandom,
            kSecUseDataProtectionKeychain:false, kSecReturnRef:true, kSecMatchLimit:kSecMatchLimitOne]
        let status = SecItemCopyMatching(query as CFDictionary, &reference)
        let key: SecKey
        if status == errSecSuccess {
            guard let reference, CFGetTypeID(reference) == SecKeyGetTypeID() else { throw IdentityError.invalidIdentity }
            key = unsafeDowncast(reference, to: SecKey.self)
        } else if status == errSecItemNotFound {
            let attrs:[CFString:Any]=[kSecAttrKeyType:kSecAttrKeyTypeECSECPrimeRandom,kSecAttrKeySizeInBits:256,
                kSecUseDataProtectionKeychain:false,kSecPrivateKeyAttrs:[kSecAttrIsPermanent:true,
                    kSecAttrApplicationTag:tag,kSecAttrLabel:label,kSecAttrIsExtractable:false] as [CFString:Any]]
            var failure:Unmanaged<CFError>?
            guard let created=SecKeyCreateRandomKey(attrs as CFDictionary,&failure) else {
                throw IdentityError.store(OSStatus(failure.map {CFErrorGetCode($0.takeRetainedValue())} ?? Int(errSecInternalError)))
            }
            key = created
        } else { throw IdentityError.store(status) }
        try validatePrivateKey(key)
        let certificate = try LocalCertificate.issue(for: key)
        try check(SecItemAdd([kSecClass:kSecClassCertificate, kSecValueRef:certificate,
            kSecAttrLabel:label, kSecUseDataProtectionKeychain:false] as CFDictionary, nil))
        guard let identity = try load() else { throw IdentityError.identityAssociation }
        return identity
    }
    private func load() throws -> SecIdentity? {
        var item: CFTypeRef?
        let status = SecItemCopyMatching([kSecClass:kSecClassIdentity, kSecAttrLabel:label,
            kSecUseDataProtectionKeychain:false, kSecReturnRef:true, kSecMatchLimit:kSecMatchLimitOne] as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        try check(status)
        guard let item, CFGetTypeID(item) == SecIdentityGetTypeID() else { throw IdentityError.invalidIdentity }
        let identity = unsafeDowncast(item, to: SecIdentity.self)
        var key: SecKey?
        guard SecIdentityCopyPrivateKey(identity,&key) == errSecSuccess, let key else { throw IdentityError.invalidIdentity }
        try validatePrivateKey(key)
        return identity
    }
    private func validatePrivateKey(_ key: SecKey) throws {
        // SecKeyCopyAttributes describes a key handle; persistence policy belongs to its Keychain item.
        var item:CFTypeRef?
        let query:[CFString:Any]=[kSecClass:kSecClassKey,kSecValueRef:key,
            kSecUseDataProtectionKeychain:false,kSecReturnAttributes:true,kSecReturnRef:true,kSecMatchLimit:kSecMatchLimitOne]
        try check(SecItemCopyMatching(query as CFDictionary,&item))
        guard let attrs=item as? [String:Any] else {throw IdentityError.invalidKeyAttributes(.attributes)}
        let handle=SecKeyCopyAttributes(key) as? [String:Any]
        guard let extractable=handle?[kSecAttrIsExtractable as String] as? Bool else {throw IdentityError.invalidKeyAttributes(.extractableMissing)}
        guard !extractable else {throw IdentityError.invalidKeyAttributes(.extractable)}
        guard attrs[kSecAttrKeySizeInBits as String] as? Int == 256 else {throw IdentityError.invalidKeyAttributes(.size)}
        guard KeyAttributeValue.isECPrimeRandom(attrs[kSecAttrKeyType as String]) else {throw IdentityError.invalidKeyAttributes(.type)}
        guard attrs[kSecAttrApplicationTag as String] as? Data == Data(label.utf8) else {throw IdentityError.invalidKeyAttributes(.tag)}
    }
    public static func pin(of identity: SecIdentity) throws -> Data {
        var cert: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &cert) == errSecSuccess, let cert,
              let key = SecCertificateCopyKey(cert), let pin = PeerPin.digest(key:key) else { throw IdentityError.invalidIdentity }
        return pin
    }
    private var trustQuery: [CFString: Any] { [kSecClass:kSecClassGenericPassword, kSecAttrService:service,
        kSecAttrAccount:"diagnostic-peer", kSecUseDataProtectionKeychain:false] }
    public func trustedPeer(localPin: Data) throws -> Data? {
        var query = trustQuery; query[kSecReturnData] = true; query[kSecMatchLimit] = kSecMatchLimitOne
        var item: CFTypeRef?; let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }; try check(status)
        guard let data = item as? Data, data.count == 64, data.prefix(32) == localPin else { throw IdentityError.invalidIdentity }
        return Data(data.suffix(32))
    }
    /// A single approved peer for diagnostics. Existing pins can only change through explicit forget.
    public func confirm(localPin: Data, peerPin: Data, oobConfirmed: Bool, mutualTLS: Bool) throws {
        guard oobConfirmed, mutualTLS, localPin.count == 32, peerPin.count == 32 else { throw IdentityError.oobRequired }
        if let old = try trustedPeer(localPin:localPin) {
            guard old == peerPin else { throw IdentityError.keyChanged }; return
        }
        var query = trustQuery; query[kSecValueData] = localPin + peerPin
        try check(SecItemAdd(query as CFDictionary, nil))
    }
    public func forgetPeer() throws {
        let status = SecItemDelete(trustQuery as CFDictionary)
        if status != errSecItemNotFound { try check(status) }
    }
}
#endif
