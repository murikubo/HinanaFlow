import Foundation

public enum FileEvent {case send(ControlMessage),consent(String,Int),startSending,saved(URL),delivered,denied}
public enum FilePumpItem {case chunk(FileChunk),end(ControlMessage)}
/// One file total at a time, either direction. Text consent remains independent.
public struct FileTransfer {
    public static let maximumSize=10_000_000 // decimal 10 MB
    private struct Incoming {let id:String;let size:Int;let hash:String;let name:String;var accepted=false;var deadline:Double;var end:Double}
    private struct Outgoing {let id:String;let snapshot:FileSnapshot;var accepted=false;var receipt=false;var offset=0;var deadline:Double;var end:Double}
    private var incoming:Incoming?
    private var outgoing:Outgoing?
    private var sink:IncomingFile?
    private var seen=Set<String>()
    private let authenticated:Bool
    public init(authenticated:Bool) {self.authenticated=authenticated}
    public var busy:Bool {incoming != nil || outgoing != nil}
    public var needsConsent:Bool {incoming.map {!$0.accepted} ?? false}
    public var sending:Bool {outgoing.map {$0.accepted && !$0.receipt} ?? false}
    public func expired(now:Double) -> Bool {
        (incoming.map {now >= $0.deadline || now >= $0.end} ?? false) || (outgoing.map {now >= $0.deadline || now >= $0.end} ?? false)
    }
    private mutating func remember(_ id:String,now:Double) throws {
        guard authenticated,!expired(now:now),seen.count<1024,seen.insert(id).inserted else {throw FileTransferError.invalid}
    }
    public mutating func cancel() {sink?.abort();sink=nil;incoming=nil;outgoing=nil}
    public mutating func offer(_ snapshot:FileSnapshot,now:Double) throws -> ControlMessage {
        guard authenticated,!busy,!expired(now:now),snapshot.size<=Self.maximumSize else {throw FileTransferError.invalid}
        let message=try ControlMessage.make("fileOfferUnicode",["name":.string(snapshot.name),"size":.integer(snapshot.size),"sha256":.string(snapshot.sha256)])
        try remember(message.id,now:now)
        outgoing=Outgoing(id:message.id,snapshot:snapshot,deadline:now+60,end:now+180)
        return message
    }
    public mutating func decide(_ accept:Bool,storage:TransferStorage,now:Double) throws -> ControlMessage {
        guard authenticated,!expired(now:now),var offer=incoming,!offer.accepted else {throw FileTransferError.invalid}
        // Allocate the private sink before putting approval on the wire.
        if accept {sink=try IncomingFile(storage:storage,size:offer.size,sha256:offer.hash);offer.accepted=true;offer.deadline=now+15;offer.end=now+120;incoming=offer}
        else {incoming=nil}
        let message=try ControlMessage.make("fileDecision",["offerId":.string(offer.id),"accept":.boolean(accept)])
        try remember(message.id,now:now);return message
    }
    public mutating func receive(_ message:ControlMessage,now:Double) throws -> [FileEvent] {
        try remember(message.id,now:now)
        switch message.type {
        case "fileOffer", "fileOfferUnicode":
            guard !busy else {throw FileTransferError.invalid}
            let size=try message.integer("size")
            guard (0...Self.maximumSize).contains(size) else {throw FileTransferError.invalid}
            incoming=Incoming(id:message.id,size:size,hash:try message.string("sha256"),name:try SharedFilename.normalize(message.string("name")),deadline:now+60,end:now+180)
            return [.consent(try message.string("name"),size)]
        case "fileDecision":
            guard var offer=outgoing,!offer.accepted,try message.string("offerId")==offer.id else {throw FileTransferError.invalid}
            if try !message.boolean("accept") {outgoing=nil;return [.denied]}
            offer.accepted=true;offer.deadline=now+15;offer.end=now+120;outgoing=offer;return [.startSending]
        case "fileEnd":
            guard let offer=incoming,offer.accepted,let sink,try message.string("offerId")==offer.id else {throw FileTransferError.invalid}
            let url=try sink.finish(finalName:"received-"+offer.id+".bin",displayName:offer.name)
            self.sink=nil;incoming=nil
            let response=try ControlMessage.make("fileReceipt",["offerId":.string(offer.id)])
            try remember(response.id,now:now);return [.saved(url),.send(response)]
        case "fileReceipt":
            guard let offer=outgoing,offer.receipt,try message.string("offerId")==offer.id else {throw FileTransferError.invalid}
            outgoing=nil;return [.delivered]
        case "fileCancel":
            let id=try message.string("offerId")
            guard incoming?.id==id || outgoing?.id==id else {throw FileTransferError.invalid}
            cancel();return [.denied]
        default:throw FileTransferError.invalid
        }
    }
    public mutating func receive(_ chunk:FileChunk,now:Double) throws {
        guard authenticated,!expired(now:now),var offer=incoming,offer.accepted,let sink,chunk.offerID==offer.id else {throw FileTransferError.invalid}
        try sink.append(offset:chunk.offset,data:chunk.data)
        offer.deadline=now+15;incoming=offer
    }
    /// Called once per completed native write: at most one chunk is queued at a time.
    public mutating func next(now:Double) throws -> FilePumpItem {
        guard authenticated,!expired(now:now),var offer=outgoing,offer.accepted,!offer.receipt else {throw FileTransferError.invalid}
        offer.deadline=now+15
        if let data=try offer.snapshot.next() {
            let chunk=try FileChunk(offerID:offer.id,offset:offer.offset,data:data)
            offer.offset+=data.count;outgoing=offer;return .chunk(chunk)
        }
        guard offer.offset==offer.snapshot.size else {throw FileTransferError.integrity}
        offer.receipt=true;outgoing=offer
        let message=try ControlMessage.make("fileEnd",["offerId":.string(offer.id)])
        try remember(message.id,now:now);return .end(message)
    }
}
