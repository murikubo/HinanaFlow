import Foundation
import Security

public enum IdentityAttribute:String, Sendable { case attributes, token, extractableMissing, extractable, size, type, tag }
public enum IdentityError: Error { case store(OSStatus), invalidIdentity, invalidKeyAttributes(IdentityAttribute), identityAssociation, keyChanged, oobRequired }

/// RFC 5280 X.509 encoding only; signatures, randomness and key operations use Security.framework.
/// No private key bytes are exported. This is not a pairing cryptosystem.
public enum LocalCertificate {
    private static func der(_ tag: UInt8, _ content: Data) -> Data {
        var length = Data()
        if content.count < 128 { length.append(UInt8(content.count)) }
        else {
            var n = content.count; var bytes: [UInt8] = []
            while n > 0 { bytes.insert(UInt8(n & 255), at: 0); n >>= 8 }
            length.append(0x80 | UInt8(bytes.count)); length.append(contentsOf: bytes)
        }
        return Data([tag]) + length + content
    }
    private static func seq(_ content: Data) -> Data { der(0x30, content) }
    private static func hex(_ s: String) -> Data {
        let a = Array(s); return Data(stride(from: 0, to: a.count, by: 2).map { UInt8(String(a[$0...$0+1]), radix: 16)! })
    }
    public static func issue(for key: SecKey, now: Date = Date()) throws -> SecCertificate {
        guard let pub = SecKeyCopyPublicKey(key), let point = SecKeyCopyExternalRepresentation(pub, nil) as Data?,
              PeerPin.digest(key: pub) != nil else { throw IdentityError.invalidIdentity }
        let algorithm = hex("300a06082a8648ce3d040302") // ecdsa-with-SHA256
        let name = seq(der(0x31, seq(hex("0603550403") + der(0x0c, Data("Hinana Flow local identity".utf8)))))
        let formatter = DateFormatter(); formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.calendar = Calendar(identifier:.gregorian); formatter.timeZone = TimeZone(secondsFromGMT: 0); formatter.dateFormat = "yyyyMMddHHmmss'Z'"
        func date(_ d: Date) -> Data { der(0x18, Data(formatter.string(from: d).utf8)) }
        var serial = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, serial.count, &serial) == errSecSuccess else { throw IdentityError.invalidIdentity }
        serial[0] = (serial[0] & 0x7f) | 1
        let spki = seq(hex("301306072a8648ce3d020106082a8648ce3d030107") + der(0x03, Data([0]) + point))
        let extensions = der(0xa3, seq(
            seq(hex("0603551d130101ff") + der(0x04, seq(Data()))) + // basicConstraints CA=false
            seq(hex("0603551d0f0101ff") + der(0x04, der(0x03, Data([7, 0x80])))) +
            seq(hex("0603551d25") + der(0x04, seq(hex("06082b0601050507030106082b06010505070302"))))))
        let tbs = seq(der(0xa0, der(0x02, Data([2]))) + der(0x02, Data(serial)) + algorithm + name +
            seq(date(now.addingTimeInterval(-300)) + date(now.addingTimeInterval(365*86400))) + name + spki + extensions)
        guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, tbs as CFData, nil) as Data?,
              SecKeyVerifySignature(pub, .ecdsaSignatureMessageX962SHA256, tbs as CFData, signature as CFData, nil),
              let certificate = SecCertificateCreateWithData(nil, seq(tbs + algorithm + der(0x03, Data([0]) + signature)) as CFData),
              let certKey = SecCertificateCopyKey(certificate), PeerPin.digest(key: certKey) == PeerPin.digest(key: pub)
        else { throw IdentityError.invalidIdentity }
        return certificate
    }
}

