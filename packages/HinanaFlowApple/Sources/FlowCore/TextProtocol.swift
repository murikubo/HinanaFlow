import Foundation

public enum TextEvent: Sendable {
    case send(ControlMessage), consent(String, Int, Int), received(String), delivered, denied
}
/// One offer per direction; no body crosses the wire until an explicit receiver decision.
public struct TextProtocol {
    private struct Incoming { let id: String; let bytes: Int; let scalars: Int; var accepted = false; var deadline: Double }
    private struct Outgoing { let id: String; let text: String; var awaitingReceipt = false; var deadline: Double }
    private var incoming: Incoming?
    private var outgoing: Outgoing?
    private var seen = Set<String>()
    private let authenticated: Bool
    public init(authenticated: Bool) { self.authenticated = authenticated }
    public var hasOutgoing: Bool { outgoing != nil }
    public var hasIncoming: Bool { incoming != nil }
    public var needsConsent: Bool { incoming.map { !$0.accepted } ?? false }
    public func expired(now: Double) -> Bool {
        (incoming.map { now >= $0.deadline } ?? false) || (outgoing.map { now >= $0.deadline } ?? false)
    }
    private mutating func remember(_ id: String) throws {
        guard authenticated, seen.count < 1024, seen.insert(id).inserted else { throw FlowError.untrusted }
    }
    public mutating func offer(text: String, now: Double) throws -> ControlMessage {
        guard authenticated, !expired(now:now), outgoing == nil, (1...8192).contains(text.unicodeScalars.count), (1...32768).contains(text.utf8.count) else { throw FlowError.untrusted }
        let message = try ControlMessage.make("textOffer", ["byteCount":.integer(text.utf8.count),"scalarCount":.integer(text.unicodeScalars.count)])
        try remember(message.id)
        outgoing = Outgoing(id:message.id, text:text, deadline:now+60)
        return message
    }
    public mutating func decide(accept: Bool, now: Double) throws -> ControlMessage {
        guard authenticated, !expired(now:now), var offer = incoming, !offer.accepted, now < offer.deadline else { throw FlowError.untrusted }
        let response = try ControlMessage.make("decision", ["offerId":.string(offer.id),"accept":.boolean(accept)])
        try remember(response.id)
        if accept { offer.accepted = true; offer.deadline = now+10; incoming = offer } else { incoming = nil }
        return response
    }
    public mutating func receive(_ message: ControlMessage, now: Double) throws -> [TextEvent] {
        guard !expired(now:now) else { throw FlowError.untrusted }
        try remember(message.id)
        switch message.type {
        case "textOffer":
            guard incoming == nil else { throw FlowError.untrusted }
            let bytes = try message.integer("byteCount"), scalars = try message.integer("scalarCount")
            guard bytes >= scalars, bytes <= scalars*4 else { throw FlowError.invalidFrame }
            incoming = Incoming(id:message.id, bytes:bytes, scalars:scalars, deadline:now+60)
            return [.consent(message.id, bytes, scalars)]
        case "decision":
            guard var offer = outgoing, !offer.awaitingReceipt, try message.string("offerId") == offer.id else { throw FlowError.untrusted }
            if try !message.boolean("accept") { outgoing = nil; return [.denied] }
            let body = try ControlMessage.make("textData", ["offerId":.string(offer.id),"text":.string(offer.text)])
            try remember(body.id); offer.awaitingReceipt = true; offer.deadline = now+10; outgoing = offer
            return [.send(body)]
        case "textData":
            guard let offer = incoming, offer.accepted, try message.string("offerId") == offer.id else { throw FlowError.untrusted }
            let text = try message.string("text")
            guard text.utf8.count == offer.bytes, text.unicodeScalars.count == offer.scalars else { throw FlowError.invalidFrame }
            let receipt = try ControlMessage.make("receipt", ["offerId":.string(offer.id)])
            try remember(receipt.id); incoming = nil
            return [.received(text), .send(receipt)]
        case "receipt":
            guard let offer = outgoing, offer.awaitingReceipt, try message.string("offerId") == offer.id else { throw FlowError.untrusted }
            outgoing = nil; return [.delivered]
        case "cancel":
            let id = try message.string("offerId")
            if incoming?.id == id { incoming = nil }
            else if outgoing?.id == id { outgoing = nil }
            else { throw FlowError.untrusted }
            return [.denied]
        default: throw FlowError.untrusted // includes hello, error, fileOffer and every unimplemented type
        }
    }
}
