import Foundation

public enum WireValue: Sendable, Equatable, Encodable {
    case string(String), integer(Int), boolean(Bool)
    public func encode(to encoder: any Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self { case .string(let v): try c.encode(v)
        case .integer(let v): try c.encode(v)
        case .boolean(let v): try c.encode(v) }
    }
}
public struct ControlMessage: Sendable {
    public let fields: [String: WireValue]
    public func string(_ key: String) throws -> String {
        guard case .string(let v) = fields[key] else { throw FlowError.invalidFrame }; return v
    }
    public func integer(_ key: String) throws -> Int {
        guard case .integer(let v) = fields[key] else { throw FlowError.invalidFrame }; return v
    }
    public func boolean(_ key: String) throws -> Bool {
        guard case .boolean(let v) = fields[key] else { throw FlowError.invalidFrame }; return v
    }
    public var type: String { (try? string("type")) ?? "" }
    public var id: String { (try? string("id")) ?? "" }
    public func encoded() throws -> Data {
        let e = JSONEncoder(); e.outputFormatting = [.sortedKeys]
        let d = try e.encode(fields); _ = try ControlJSON.parse(d); return d
    }
    public static func make(_ type: String, _ fields: [String: WireValue] = [:]) throws -> ControlMessage {
        var v = fields; v["v"] = .integer(1); v["id"] = .string(UUID().uuidString.lowercased()); v["type"] = .string(type)
        let m = ControlMessage(fields: v); _ = try m.encoded(); return m
    }
}
public enum ControlJSON {
    private static let uuid = #"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"#
    private static let filename = #"(?!.*\.\.)(?!(?:[cC][oO][nN]|[pP][rR][nN]|[aA][uU][xX]|[nN][uU][lL]|[cC][oO][mM][1-9]|[lL][pP][tT][1-9])(?:\.|$))[A-Za-z0-9](?:[A-Za-z0-9._ -]{0,118}[A-Za-z0-9_-])?"#
    private static func match(_ s: String, _ pattern: String) -> Bool {
        s.range(of: #"\A(?:"# + pattern + #")\z"#, options: .regularExpression) != nil
    }
    /// Flat object tokenizer preserves duplicate (including escaped) keys. Foundation decodes every string.
    public static func parse(_ data: Data) throws -> ControlMessage {
        guard !data.isEmpty, data.count <= 65536, String(data: data, encoding: .utf8) != nil else { throw FlowError.invalidFrame }
        let b = Array(data); var i = 0
        func space() { while i < b.count && [9,10,13,32].contains(b[i]) { i += 1 } }
        func take(_ x: UInt8) throws { space(); guard i < b.count, b[i] == x else { throw FlowError.invalidFrame }; i += 1 }
        func string() throws -> String {
            space(); let start = i; try take(34); var escaped = false
            while i < b.count {
                let c = b[i]; i += 1
                if c == 34 && !escaped {
                    return try JSONDecoder().decode(String.self, from: Data(b[start..<i]))
                }
                if c == 92 && !escaped { escaped = true } else { escaped = false }
            }
            throw FlowError.invalidFrame
        }
        try take(123); var fields: [String: WireValue] = [:]; space()
        if i < b.count && b[i] == 125 { i += 1 }
        else {
            while true {
                let key = try string(); guard fields[key] == nil else { throw FlowError.invalidFrame }
                try take(58); space(); guard i < b.count else { throw FlowError.invalidFrame }
                let value: WireValue
                if b[i] == 34 { value = .string(try string()) }
                else {
                    let start = i
                    while i < b.count && ![9,10,13,32,44,125].contains(b[i]) { i += 1 }
                    let token = String(decoding: b[start..<i], as: UTF8.self)
                    if token == "true" { value = .boolean(true) }
                    else if token == "false" { value = .boolean(false) }
                    else if match(token, "0|[1-9][0-9]*"), let n = Int(token) { value = .integer(n) }
                    else { throw FlowError.invalidFrame }
                }
                fields[key] = value; space()
                guard i < b.count else { throw FlowError.invalidFrame }
                if b[i] == 125 { i += 1; break }
                try take(44)
            }
        }
        space(); guard i == b.count else { throw FlowError.invalidFrame }
        let m = ControlMessage(fields: fields)
        guard fields["v"] == .integer(1), match(try m.string("id"), uuid) else { throw FlowError.invalidFrame }
        let extras: [String]
        switch m.type {
        case "hello":
            extras = ["deviceId","displayName"]
            guard match(try m.string("deviceId"), uuid), (1...64).contains(try m.string("displayName").unicodeScalars.count) else { throw FlowError.invalidFrame }
        case "textOffer":
            extras = ["byteCount","scalarCount"]
            guard (1...32768).contains(try m.integer("byteCount")), (1...8192).contains(try m.integer("scalarCount")) else { throw FlowError.invalidFrame }
        case "textData":
            extras = ["offerId","text"]
            guard match(try m.string("offerId"), uuid), (1...8192).contains(try m.string("text").unicodeScalars.count) else { throw FlowError.invalidFrame }
        case "fileOfferUnicode":
            extras = ["name","size","sha256"]
            guard SharedFilename.valid(try m.string("name")), (0...10_000_000).contains(try m.integer("size")), match(try m.string("sha256"), "[0-9a-f]{64}") else {throw FlowError.invalidFrame}
        case "fileOffer":
            extras = ["name","size","sha256"]
            guard match(try m.string("name"), filename), (0...1073741824).contains(try m.integer("size")), match(try m.string("sha256"), "[0-9a-f]{64}") else { throw FlowError.invalidFrame }
        case "decision":
            extras = ["offerId","accept"]; _ = try m.boolean("accept")
            guard match(try m.string("offerId"), uuid) else { throw FlowError.invalidFrame }
        case "fileDecision":
            extras = ["offerId","accept"]; _ = try m.boolean("accept")
            guard match(try m.string("offerId"), uuid) else { throw FlowError.invalidFrame }
        case "receipt", "cancel", "fileEnd", "fileReceipt", "fileCancel":
            extras = ["offerId"]; guard match(try m.string("offerId"), uuid) else { throw FlowError.invalidFrame }
        case "error":
            extras = ["code"]; guard ["unsupported","denied","invalid","timeout","integrity"].contains(try m.string("code")) else { throw FlowError.invalidFrame }
        default: throw FlowError.invalidFrame
        }
        guard Set(fields.keys) == Set(["v","type","id"] + extras) else { throw FlowError.invalidFrame }
        return m
    }
}
