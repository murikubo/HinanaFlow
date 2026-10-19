import Foundation
import Security

/// Shared Secure Enclave identity store for signed macOS and iOS apps.
/// The historic type name is retained for source compatibility.
/// Secure Enclave is mandatory. There is no software-key or simulator fallback.
@MainActor public final class IOSIdentityStore: AppleIdentityStore {
    private let label:String
    private let service:String
    public init(profile:ValidationProfile = .production) {
        label=profile.identityLabel;service=profile.trustService
    }
    private func check(_ status:OSStatus) throws {
        guard status==errSecSuccess else {throw IdentityError.store(status)}
    }
    private var keyQuery:[CFString:Any] {
        [kSecClass:kSecClassKey,kSecAttrApplicationTag:Data(label.utf8),
         kSecAttrKeyClass:kSecAttrKeyClassPrivate,kSecAttrKeyType:kSecAttrKeyTypeECSECPrimeRandom,
         kSecUseDataProtectionKeychain:true,kSecAttrSynchronizable:false,kSecReturnRef:true,kSecMatchLimit:kSecMatchLimitOne]
    }
    public func loadOrCreate() throws -> SecIdentity {
        #if targetEnvironment(simulator)
        throw IdentityError.store(errSecNotAvailable)
        #else
        if let identity=try loadIdentity() {return identity}
        var item:CFTypeRef?
        let status=SecItemCopyMatching(keyQuery as CFDictionary,&item)
        let key:SecKey
        if status==errSecSuccess {
            guard let item,CFGetTypeID(item)==SecKeyGetTypeID() else {throw IdentityError.invalidIdentity}
            key=unsafeDowncast(item,to:SecKey.self)
        } else if status==errSecItemNotFound {
            guard let control=SecAccessControlCreateWithFlags(nil,kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage],nil) else {throw IdentityError.invalidIdentity}
            let attributes:[CFString:Any]=[
                kSecAttrKeyType:kSecAttrKeyTypeECSECPrimeRandom,kSecAttrKeySizeInBits:256,
                kSecAttrTokenID:kSecAttrTokenIDSecureEnclave,kSecUseDataProtectionKeychain:true,
                kSecPrivateKeyAttrs:[kSecAttrIsPermanent:true,kSecAttrApplicationTag:Data(label.utf8),
                    kSecAttrLabel:label,kSecAttrAccessControl:control] as [CFString:Any]
            ]
            guard let created=SecKeyCreateRandomKey(attributes as CFDictionary,nil) else {throw IdentityError.invalidIdentity}
            key=created
        } else {throw IdentityError.store(status)}
        try validate(key)
        // The certificate is public. Sign through the Secure Enclave handle; never export the private key.
        let cert=try LocalCertificate.issue(for:key)
        try check(SecItemAdd([kSecClass:kSecClassCertificate,kSecValueRef:cert,kSecAttrLabel:label,kSecUseDataProtectionKeychain:true,
            kSecAttrAccessible:kSecAttrAccessibleWhenUnlockedThisDeviceOnly,kSecAttrSynchronizable:false] as CFDictionary,nil))
        guard let identity=try loadIdentity() else {throw IdentityError.invalidIdentity}
        return identity
        #endif
    }
    private func loadIdentity() throws -> SecIdentity? {
        var item:CFTypeRef?
        // Keychain synthesizes SecIdentity from matching certificate public-key hash / private-key application label.
        let status=SecItemCopyMatching([kSecClass:kSecClassIdentity,kSecAttrLabel:label,kSecUseDataProtectionKeychain:true,kSecAttrSynchronizable:false,
            kSecReturnRef:true,kSecMatchLimit:kSecMatchLimitOne] as CFDictionary,&item)
        if status==errSecItemNotFound {return nil};try check(status)
        guard let item,CFGetTypeID(item)==SecIdentityGetTypeID() else {throw IdentityError.invalidIdentity}
        let identity=unsafeDowncast(item,to:SecIdentity.self)
        var key:SecKey?
        guard SecIdentityCopyPrivateKey(identity,&key)==errSecSuccess,let key else {throw IdentityError.invalidIdentity}
        try validate(key)
        return identity
    }
    private func validate(_ key:SecKey) throws {
        guard let handle=SecKeyCopyAttributes(key) as? [String:Any],
              handle[kSecAttrTokenID as String] as? String == kSecAttrTokenIDSecureEnclave as String
        else {throw IdentityError.invalidKeyAttributes(.token)}
        var query=keyQuery;query[kSecReturnAttributes]=true
        var item:CFTypeRef?;try check(SecItemCopyMatching(query as CFDictionary,&item))
        guard let a=item as? [String:Any],let stored=a[kSecValueRef as String],
              CFGetTypeID(stored as CFTypeRef)==SecKeyGetTypeID(),
              let originalPublic=SecKeyCopyPublicKey(key),
              let storedPublic=SecKeyCopyPublicKey(unsafeDowncast(stored as AnyObject,to:SecKey.self)),
              let originalPin=PeerPin.digest(key:originalPublic),originalPin==PeerPin.digest(key:storedPublic)
        else {throw IdentityError.invalidKeyAttributes(.attributes)}
        guard KeyAttributeValue.isECPrimeRandom(a[kSecAttrKeyType as String]) else {throw IdentityError.invalidKeyAttributes(.type)}
        guard a[kSecAttrKeySizeInBits as String] as? Int == 256 else {throw IdentityError.invalidKeyAttributes(.size)}
        guard a[kSecAttrApplicationTag as String] as? Data == Data(label.utf8) else {throw IdentityError.invalidKeyAttributes(.tag)}
        if let extractable=a[kSecAttrIsExtractable as String] as? Bool,extractable {throw IdentityError.invalidKeyAttributes(.extractable)}
        // Non-exportability follows from Secure Enclave token enforcement, even if the optional attribute is absent.
    }
    private var trustQuery:[CFString:Any] {
        [kSecClass:kSecClassGenericPassword,kSecUseDataProtectionKeychain:true,kSecAttrService:service,kSecAttrAccount:"diagnostic-peer",kSecAttrSynchronizable:false]
    }
    public func trustedPeer(localPin:Data) throws -> Data? {
        var query=trustQuery;query[kSecReturnData]=true;query[kSecMatchLimit]=kSecMatchLimitOne
        var item:CFTypeRef?;let status=SecItemCopyMatching(query as CFDictionary,&item)
        if status==errSecItemNotFound {return nil};try check(status)
        guard localPin.count==32,let data=item as? Data,data.count==64,data.prefix(32)==localPin else {throw IdentityError.invalidIdentity}
        return Data(data.suffix(32))
    }
    public func confirm(localPin:Data,peerPin:Data,oobConfirmed:Bool,mutualTLS:Bool) throws {
        guard oobConfirmed,mutualTLS,localPin.count==32,peerPin.count==32 else {throw IdentityError.oobRequired}
        if let old=try trustedPeer(localPin:localPin) {guard old==peerPin else {throw IdentityError.keyChanged};return}
        var query=trustQuery;query[kSecValueData]=localPin+peerPin
        query[kSecAttrAccessible]=kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        try check(SecItemAdd(query as CFDictionary,nil))
    }
    public func forgetPeer() throws {
        let status=SecItemDelete(trustQuery as CFDictionary)
        if status != errSecItemNotFound {try check(status)}
    }
}
