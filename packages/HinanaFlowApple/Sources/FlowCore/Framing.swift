import Foundation

public enum FlowError: Error { case invalidFrame, incompleteFrame, untrusted, invalidAddress }

/// Legacy control-only framing. The new approved-file profile uses TransferDecoder.
public struct ControlDecoder {
    private var header = Data()
    private var body = Data()
    private var expected: Int?
    public init() {}
    public var hasPartialFrame: Bool { !header.isEmpty || expected != nil }
    public mutating func feed(_ bytes: Data) throws -> [Data] {
        var frames: [Data] = []
        for byte in bytes {
            if let length = expected {
                body.append(byte)
                if body.count == length {
                    frames.append(body)
                    body = Data(); header = Data(); expected = nil
                }
            } else {
                header.append(byte)
                if header.count == 5 {
                    let size = header.dropFirst().reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
                    guard header.first == 1, size > 0, size <= 65_536 else { throw FlowError.invalidFrame }
                    expected = Int(size)
                }
            }
        }
        return frames
    }
    public func finish() throws {
        guard header.isEmpty, expected == nil else { throw FlowError.incompleteFrame }
    }
    public static func encode(_ payload: Data) throws -> Data {
        guard !payload.isEmpty, payload.count <= 65_536 else { throw FlowError.invalidFrame }
        let n = UInt32(payload.count)
        return Data([1, UInt8((n >> 24) & 255), UInt8((n >> 16) & 255), UInt8((n >> 8) & 255), UInt8(n & 255)]) + payload
    }
}

public enum TransferGate {
    /// Legacy file/bulk and in-band pairing gate remains closed. Desktop OOB text uses TextProtocol.
    public static let pairingEnabled = false
    public static func authorize(trusted: Bool, userApproved: Bool) -> Bool { false }
}
