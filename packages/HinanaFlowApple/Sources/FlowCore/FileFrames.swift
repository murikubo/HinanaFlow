import Foundation

public struct FileChunk:Sendable {
    public static let maximumData = 32768
    public let offerID:String
    public let offset:Int
    public let data:Data
    public init(offerID:String,offset:Int,data:Data) throws {
        guard let id=UUID(uuidString:offerID),id.uuidString.lowercased()==offerID,
              offset>=0,offset<=FileTransfer.maximumSize,!data.isEmpty,data.count<=Self.maximumData else {throw FlowError.invalidFrame}
        self.offerID=offerID;self.offset=offset;self.data=data
    }
    public func encoded() -> Data {
        var uuid=UUID(uuidString:offerID)!.uuid
        let id=withUnsafeBytes(of:&uuid) {Data($0)}
        let n=UInt64(offset)
        return id+Data((0..<8).reversed().map {UInt8(truncatingIfNeeded:n >> ($0*8))})+data
    }
    public init(payload:Data) throws {
        guard payload.count>24,payload.count<=24+Self.maximumData else {throw FlowError.invalidFrame}
        let bytes=Array(payload.prefix(16));let hex=bytes.map {String(format:"%02x",$0)}.joined()
        let cuts=[8,4,4,4,12];var start=hex.startIndex;var parts=[String]()
        for count in cuts {let end=hex.index(start,offsetBy:count);parts.append(String(hex[start..<end]));start=end}
        let offset=payload.dropFirst(16).prefix(8).reduce(UInt64(0)) {($0<<8)|UInt64($1)}
        guard offset<=UInt64(FileTransfer.maximumSize) else {throw FlowError.invalidFrame}
        try self.init(offerID:parts.joined(separator:"-"),offset:Int(offset),data:Data(payload.dropFirst(24)))
    }
}
public enum TransferFrame:Sendable {case control(Data),chunk(FileChunk)}
/// Bounded multiplexed decoder. Legacy ControlDecoder remains unchanged and rejects kind 2.
public struct TransferDecoder {
    private var header=Data(),body=Data()
    private var expected:Int?
    public init() {}
    public var hasPartialFrame:Bool {!header.isEmpty || expected != nil}
    public mutating func feed(_ bytes:Data) throws -> [TransferFrame] {
        var result=[TransferFrame]()
        for byte in bytes {
            if let length=expected {
                body.append(byte)
                if body.count==length {
                    if header.first==1 {result.append(.control(body))}
                    else {result.append(.chunk(try FileChunk(payload:body)))}
                    header=Data();body=Data();expected=nil
                }
            } else {
                header.append(byte)
                if header.count==5 {
                    let n=header.dropFirst().reduce(UInt32(0)) {($0<<8)|UInt32($1)}
                    guard (header.first==1 && (1...65536).contains(n)) || (header.first==2 && (25...UInt32(24+FileChunk.maximumData)).contains(n)) else {throw FlowError.invalidFrame}
                    expected=Int(n)
                }
            }
        }
        return result
    }
    public func finish() throws {guard !hasPartialFrame else {throw FlowError.incompleteFrame}}
    public static func encode(_ chunk:FileChunk) -> Data {
        let payload=chunk.encoded(),n=UInt32(payload.count)
        return Data([2,UInt8(truncatingIfNeeded:n>>24),UInt8(truncatingIfNeeded:n>>16),UInt8(truncatingIfNeeded:n>>8),UInt8(truncatingIfNeeded:n)])+payload
    }
}
