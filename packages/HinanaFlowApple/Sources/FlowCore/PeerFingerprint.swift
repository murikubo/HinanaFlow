import Foundation
public enum PeerFingerprint {
    public static func parse(_ input:String) throws -> Data {
        let value=input.lowercased()
        guard value.utf8.count==64,value.allSatisfy({$0.isASCII && $0.isHexDigit}) else {throw FlowError.untrusted}
        let chars=Array(value)
        return Data(stride(from:0,to:64,by:2).map {UInt8(String(chars[$0...$0+1]),radix:16)!})
    }
}
