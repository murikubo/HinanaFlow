import Foundation
import Network
import Security
import CryptoKit
import FlowCore
import FlowDiagnostics

func require(_ condition: @autoclosure () throws -> Bool, _ label: String) throws {
    if try !condition() { throw NSError(domain: "VectorFailure", code: 1, userInfo: [NSLocalizedDescriptionKey: label]) }
}
func bytes(_ hex: String) -> Data {
    let chars = Array(hex)
    return Data(stride(from: 0, to: chars.count, by: 2).map { UInt8(String(chars[$0...$0+1]), radix: 16)! })
}
func mustThrow(_ label: String, _ operation: () throws -> Void) throws {
    do { try operation() } catch { return }
    throw NSError(domain: "ExpectedRejection", code: 1, userInfo: [NSLocalizedDescriptionKey: label])
}
let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
    .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
let vectors = try JSONSerialization.jsonObject(with: Data(contentsOf: root.appendingPathComponent("protocol/vectors.json"))) as! [String: Any]
var count = 0
for vector in vectors["frames"] as! [[String: Any]] {
    let input = bytes(vector["hex"] as! String), valid = vector["valid"] as! Bool
    for split in 0...input.count {
        var decoder = ControlDecoder()
        var frames: [Data] = []
        var accepted = true
        do {
            frames += try decoder.feed(Data(input.prefix(split)))
            frames += try decoder.feed(Data(input.dropFirst(split)))
            try decoder.finish()
        } catch { accepted = false }
        try require(accepted == valid, vector["name"] as! String)
        if valid { try require(frames == [bytes(vector["payloadHex"] as! String)], "payload mismatch") }
        count += 1
    }
}
let payload = Data(repeating: 65, count: 65_536)
let frame = try ControlDecoder.encode(payload)
var decoder = ControlDecoder()
let coalesced = try decoder.feed(frame + frame)
try require(coalesced == [payload, payload], "coalesced/boundary")
try decoder.finish()
try mustThrow("empty encode") { _ = try ControlDecoder.encode(Data()) }
try mustThrow("large encode") { _ = try ControlDecoder.encode(Data(repeating: 0, count: 65_537)) }
for trusted in [false, true] { for approved in [false, true] {
    try require(!TransferGate.authorize(trusted: trusted, userApproved: approved), "closed transfer gate")
}}
try require(!TransferGate.pairingEnabled, "pairing gate")
try mustThrow("empty pins") { try PinnedTLS.validateApprovedPins([]) }
try mustThrow("short pin") { try PinnedTLS.validateApprovedPins([Data([1])]) }
for host in ["10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.2", "169.254.1.1", "fe80::1", "fd00::1"] {
    try require(LANAddress.permits(host), "private IP rejected")
}
for host in ["8.8.8.8", "127.0.0.1", "172.32.0.1", "172.15.0.1", "::1", "::ffff:8.8.8.8", "example.com", "0.0.0.0"] {
    try require(!LANAddress.permits(host), "non-LAN IP accepted")
}
for vector in vectors["pins"] as! [[String: String]] {
    let attrs: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass: kSecAttrKeyClassPublic, kSecAttrKeySizeInBits: 256]
    guard let key = SecKeyCreateWithData(bytes(vector["publicKeyHex"]!) as CFData, attrs as CFDictionary, nil) else {
        fatalError("public key fixture rejected")
    }
    try require(PeerPin.digest(key: key) == bytes(vector["sha256"]!), "pin mismatch")
}
for vector in vectors["sha256"] as! [[String: String]] {
    try require(Data(SHA256.hash(data: bytes(vector["inputHex"]!))) == bytes(vector["digest"]!), "hash mismatch")
}
print("PASS: \(count) frame split cases, coalescing/boundaries, closed gates, LAN filters, public-key pin, hashes")

var jsonCases = 0
for vector in vectors["control"] as! [[String: Any]] {
    let input = bytes(vector["inputHex"] as! String)
    var accepted = true
    do { _ = try ControlJSON.parse(input) } catch { accepted = false }
    try require(accepted == (vector["valid"] as! Bool), "JSON vector: " + (vector["name"] as! String))
    jsonCases += 1
}
for vector in vectors["controlBytes"] as! [[String: Any]] {
    try mustThrow("invalid UTF8") { _ = try ControlJSON.parse(bytes(vector["hex"] as! String)) }
}
print("PASS: \(jsonCases) native Swift JSON cases and invalid UTF8 vectors")

// Crypto conformance only: memory-only keys; no keychain reads/writes or listening sockets.
#if os(macOS)
let ephemeralAttributes: [CFString:Any] = [kSecAttrKeyType:kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeySizeInBits:256,kSecAttrIsPermanent:false]
guard let ephemeralKey=SecKeyCreateRandomKey(ephemeralAttributes as CFDictionary,nil),
      let ephemeralPublic=SecKeyCopyPublicKey(ephemeralKey), let ephemeralPin=PeerPin.digest(key:ephemeralPublic)
else { fatalError("ephemeral key generation failed") }
let certificate=try LocalCertificate.issue(for:ephemeralKey)
try require(PeerPin.verifyCertificate(certificate,pin:ephemeralPin),"native self-signed cert validity")
try require(!PeerPin.verifyCertificate(certificate,pin:Data(repeating:0,count:32)),"wrong cert pin")
let expiredCertificate=try LocalCertificate.issue(for:ephemeralKey,now:Date().addingTimeInterval(-370*86400))
try require(!PeerPin.verifyCertificate(expiredCertificate,pin:ephemeralPin),"expired certificate")
let futureCertificate=try LocalCertificate.issue(for:ephemeralKey,now:Date().addingTimeInterval(86400))
try require(!PeerPin.verifyCertificate(futureCertificate,pin:ephemeralPin),"future certificate")
try require(LANBinding.sharesSubnet(local:"192.168.1.10",peer:"192.168.1.11",mask:0xffffff00),"LAN subnet")
for peer in ["192.168.2.1","192.168.1.0","192.168.1.255","192.168.1.10","8.8.8.8"] {
    try require(!LANBinding.sharesSubnet(local:"192.168.1.10",peer:peer,mask:0xffffff00),"off-subnet")
}
try require(!LANBinding.sharesSubnet(local:"10.0.0.1",peer:"10.0.0.2",mask:0xff00ff00),"noncontiguous mask")
print("PASS: memory-only X.509 issuance, native pin/validity rejection, subnet filters; keychain untouched")
#endif

func transmitted(_ events:[TextEvent]) throws -> ControlMessage {
    for event in events { if case .send(let message)=event { return message } }
    throw FlowError.invalidFrame
}
func exchange(_ sender:inout TextProtocol,_ receiver:inout TextProtocol,_ text:String,now:Double) throws {
    let offer=try sender.offer(text:text,now:now)
    try require(offer.fields["text"]==nil,"offer must not include body")
    let offered=try receiver.receive(try ControlJSON.parse(offer.encoded()),now:now+1)
    try require(offered.count==1,"offer consent event")
    if case .consent = offered[0] {} else { throw FlowError.invalidFrame }
    let decision=try receiver.decide(accept:true,now:now+2)
    let body=try transmitted(sender.receive(try ControlJSON.parse(decision.encoded()),now:now+3))
    let received=try receiver.receive(try ControlJSON.parse(body.encoded()),now:now+4)
    try require(received.contains { if case .received(let t)=$0 { return t==text }; return false },"received text")
    let receipt=try transmitted(received)
    let delivered=try sender.receive(try ControlJSON.parse(receipt.encoded()),now:now+5)
    try require(delivered.contains { if case .delivered=$0 { return true }; return false },"delivery ack")
}
var a=TextProtocol(authenticated:true), b=TextProtocol(authenticated:true)
try exchange(&a,&b,"Windows → macOS 👋",now:0)
try exchange(&b,&a,"macOS → Windows 안녕",now:10)
var unauthenticated=TextProtocol(authenticated:false)
try mustThrow("unpaired offer") { _=try unauthenticated.offer(text:"blocked",now:0) }
var c=TextProtocol(authenticated:true), d=TextProtocol(authenticated:true)
let unapproved=try c.offer(text:"secret",now:0)
_ = try d.receive(unapproved,now:1)
let premature=try ControlMessage.make("textData",["offerId":.string(unapproved.id),"text":.string("secret")])
try mustThrow("body before consent") { _=try d.receive(premature,now:2) }
var denyA=TextProtocol(authenticated:true), denyB=TextProtocol(authenticated:true)
let deniedOffer=try denyA.offer(text:"not delivered",now:0); _=try denyB.receive(deniedOffer,now:1)
let refusal=try denyB.decide(accept:false,now:2)
let refused=try denyA.receive(refusal,now:3)
try require(!refused.contains { if case .send=$0 {return true};return false },"refusal must send no body")
try mustThrow("replayed offer") { _=try denyB.receive(deniedOffer,now:4) }
var timed=TextProtocol(authenticated:true); _=try timed.offer(text:"timeout",now:0)
try require(timed.expired(now:60),"fixed offer timeout")
var badSizeA=TextProtocol(authenticated:true), badSizeB=TextProtocol(authenticated:true)
let sizeOffer=try badSizeA.offer(text:"abc",now:0); _=try badSizeB.receive(sizeOffer,now:1); _=try badSizeB.decide(accept:true,now:2)
let mismatch=try ControlMessage.make("textData",["offerId":.string(sizeOffer.id),"text":.string("abcd")])
try mustThrow("approved size mismatch") { _=try badSizeB.receive(mismatch,now:3) }
print("PASS: two-way consent/receipt state machine; unpaired, pre-consent, denial, replay, timeout, size mismatch")

try exchange(&a,&b,"\u{feff}a\u{301}👋",now:20)
var dualA=TextProtocol(authenticated:true), dualB=TextProtocol(authenticated:true)
let offerA=try dualA.offer(text:"A",now:0), offerB=try dualB.offer(text:"B",now:0)
_=try dualA.receive(offerB,now:1); _=try dualB.receive(offerA,now:1)
let decisionA=try dualA.decide(accept:true,now:2), decisionB=try dualB.decide(accept:true,now:2)
let bodyA=try transmitted(dualA.receive(decisionB,now:3)), bodyB=try transmitted(dualB.receive(decisionA,now:3))
let responseA=try dualA.receive(bodyB,now:4), responseB=try dualB.receive(bodyA,now:4)
_=try dualA.receive(transmitted(responseB),now:5); _=try dualB.receive(transmitted(responseA),now:5)
try require(!dualA.hasOutgoing && !dualB.hasOutgoing,"simultaneous completion")
let blockedFile=try ControlMessage.make("fileOffer",["name":.string("a.txt"),"size":.integer(0),"sha256":.string(String(repeating:"0",count:64))])
var filePeer=TextProtocol(authenticated:true)
try mustThrow("file remains blocked") { _=try filePeer.receive(blockedFile,now:0) }
print("PASS: native JSON encode/decode body preservation, simultaneous bidirectional offers, blocked file offer")

var consentA=TextProtocol(authenticated:true),consentB=TextProtocol(authenticated:true)
let ca=try consentA.offer(text:"A",now:0), cb=try consentB.offer(text:"B",now:0)
_=try consentA.receive(cb,now:1);_=try consentB.receive(ca,now:1)
_=try consentA.decide(accept:true,now:2)
let cancelled=try ControlMessage.make("cancel",["offerId":.string(ca.id)])
_=try consentA.receive(cancelled,now:3)
try require(consentA.hasIncoming && !consentA.needsConsent,"cancel must not re-enable already granted consent")
print("PASS: cancellation preserves opposite-direction consent state")

let authDocument=try JSONSerialization.jsonObject(with:Data(contentsOf:root.appendingPathComponent("protocol/apple-auth-vectors.json"))) as! [String:Any]
let authCases=authDocument["cases"] as! [[String:Any]]
for vector in authCases {
    var auth=AuthenticationState();var rejected=false
    for step in vector["steps"] as! [[String:Any]] {
        do {
            switch step["op"] as! String {
            case "active":auth.setActive(step["value"] as! Bool)
            case "begin":
                let local=Data(repeating:1,count:32)
                let peer:Data=switch step["peer"] as? String {case "self":local;case "short":Data([2]);default:Data(repeating:2,count:32)}
                let stored:Data?=switch step["stored"] as? String {case "same":Data(repeating:2,count:32);case "other":Data(repeating:3,count:32);case "short":Data([2]);default:nil}
                try auth.begin(localPin:local,expectedPeer:peer,storedPeer:stored,oobConfirmed:step["oob"] as? Bool ?? false)
            case "tls":
                let pin=Data(repeating:step["peer"] as? String == "other" ? 3:2,count:32)
                try auth.nativeTLSReady(TLSPeerEvidence(peerPin:pin,tls13:step["tls13"] as? Bool ?? true,
                    peerCertificateVerified:step["peerVerified"] as? Bool ?? true,
                    localIdentityPresented:step["localPresented"] as? Bool ?? true))
            case "persist":try auth.trustPersisted()
            case "close":auth.close()
            default:fatalError("unknown test operation")
            }
        } catch {rejected=true;break}
    }
    try require(rejected == vector["expectedError"] as! Bool,"auth rejection: "+(vector["name"] as! String))
    try require(auth.maySendApplicationData == vector["expectedReady"] as! Bool,"auth ready: "+(vector["name"] as! String))
    if !auth.maySendApplicationData {try mustThrow("application data gate") {try auth.requireApplicationData()}}
}
for value in ["",String(repeating:"a",count:63),String(repeating:"g",count:64),String(repeating:"a",count:65),String(repeating:"ａ",count:64)] {
    try mustThrow("invalid fingerprint") {_=try PeerFingerprint.parse(value)}
}
let parsedUpperPin=try PeerFingerprint.parse(String(repeating:"A",count:64))
try require(parsedUpperPin == Data(repeating:0xaa,count:32),"full fingerprint case")
print("PASS: \(authCases.count) shared authentication/lifecycle vectors; OOB + native TLS + persisted trust gate")

@MainActor final class NoKeychainStore:AppleIdentityStore {
    var calls=0
    func loadOrCreate() throws -> SecIdentity {calls+=1;throw IdentityError.invalidIdentity}
    func trustedPeer(localPin:Data) throws -> Data? {calls+=1;throw IdentityError.invalidIdentity}
    func confirm(localPin:Data,peerPin:Data,oobConfirmed:Bool,mutualTLS:Bool) throws {calls+=1;throw IdentityError.invalidIdentity}
    func forgetPeer() throws {calls+=1;throw IdentityError.invalidIdentity}
}
try await MainActor.run {
    let store=NoKeychainStore();let model=AppleDiagnosticModel(store:store)
    model.prepare();model.start(listen:false);model.send();model.decide(true);model.forget()
    try require(store.calls==0 && !model.connected && !model.busy,"inactive model must not access store or open network")
    model.setActive(true);model.prepare()
    try require(store.calls==1 && model.fingerprint.isEmpty && !model.connected,"store failure must fail closed")
    model.draft="private draft";model.receivedText="private body"
    model.setActive(false)
    try require(model.draft.isEmpty && model.receivedText.isEmpty && !model.canSend && !model.awaitingApproval,"background must clear content and consent")
    model.setActive(true)
    try require(!model.connected && !model.busy && store.calls==1,"activation must not auto-reconnect or load keys")
}
print("PASS: actual shared diagnostic model inactive/activation/failing-store checks (injected store; no Keychain or network I/O)")

let expectedEndpoint=NWEndpoint.hostPort(host:.ipv4(IPv4Address("192.168.1.20")!),port:.init(rawValue:45731)!)
try require(LANBinding.peerMatches(expectedEndpoint,expected:"192.168.1.20"),"typed peer IPv4 match")
try require(!LANBinding.peerMatches(expectedEndpoint,expected:"192.168.1.21"),"wrong peer IPv4")
let namedEndpoint=NWEndpoint.hostPort(host:.name("example.com",nil),port:.init(rawValue:45731)!)
try require(!LANBinding.peerMatches(namedEndpoint,expected:"192.168.1.20"),"no named peer fallback")
print("PASS: typed peer endpoint checks without DNS resolution or network I/O")

for value:Any in [kSecAttrKeyTypeECSECPrimeRandom as String,NSNumber(value:73)] {
    try require(KeyAttributeValue.isECPrimeRandom(value),"EC type attribute representation")
}
for value:Any in ["RSA", "073", NSNumber(value:42), NSNumber(value:73.5), true, Data()] {
    try require(!KeyAttributeValue.isECPrimeRandom(value),"invalid EC type attribute")
}
try require(!KeyAttributeValue.isECPrimeRandom(nil),"missing EC type attribute")
print("PASS: strict Keychain numeric/string key-type attribute regression checks")

// Single-file profile: real app-owned filesystem I/O, no Keychain, no network or external user files.
let fileVectors=try JSONSerialization.jsonObject(with:Data(contentsOf:root.appendingPathComponent("protocol/file-vectors.json"))) as! [String:Any]
for vector in fileVectors["frames"] as! [[String:Any]] {
    let data=bytes(vector["hex"] as! String),valid=vector["valid"] as! Bool
    for split in 0...data.count {
        var d=TransferDecoder();var accepted=true
        do {_=try d.feed(Data(data.prefix(split)));_=try d.feed(Data(data.dropFirst(split)));try d.finish()}
        catch {accepted=false}
        try require(accepted==valid,"file frame split: "+(vector["name"] as! String))
    }
}
let fileTestDirectory=root.appendingPathComponent(".build/file-tests-"+UUID().uuidString.lowercased(),isDirectory:true)
try FileManager.default.createDirectory(at:fileTestDirectory,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
defer {try? FileManager.default.removeItem(at:fileTestDirectory)}
func hashHex(_ data:Data)->String {SHA256.hash(data:data).map {String(format:"%02x",$0)}.joined()}
func newStorage(_ name:String) throws -> TransferStorage {try TransferStorage(directory:fileTestDirectory.appendingPathComponent(name))}
let senderStorage=try newStorage("sender"),receiverStorage=try newStorage("receiver")
let sourceURL=fileTestDirectory.appendingPathComponent("source.bin")
for size in [0,1,32768,65539,FileTransfer.maximumSize] {
    let content=Data((0..<size).map {UInt8(truncatingIfNeeded:$0)})
    try content.write(to:sourceURL)
    let source=try FileSnapshot(source:sourceURL,storage:senderStorage)
    if size==65539 {try Data([99]).write(to:sourceURL)} // source mutation must not alter the offered snapshot
    var sender=FileTransfer(authenticated:true),receiver=FileTransfer(authenticated:true)
    let offer=try sender.offer(source,now:0)
    _=try receiver.receive(ControlJSON.parse(offer.encoded()),now:0)
    try require(receiver.needsConsent,"file must need per-file approval")
    try mustThrow("no body before file approval") {_=try sender.next(now:1)}
    let decision=try receiver.decide(true,storage:receiverStorage,now:1)
    _=try sender.receive(ControlJSON.parse(decision.encoded()),now:1)
    var saved:URL?,receipt:ControlMessage?
    while true {
        switch try sender.next(now:2) {
        case .chunk(let chunk):
            var decoder=TransferDecoder()
            let frame=TransferDecoder.encode(chunk)
            let decoded=try decoder.feed(frame)
            guard case .chunk(let received)=decoded.first else {throw FileTransferError.invalid}
            try receiver.receive(received,now:2)
        case .end(let end):
            for event in try receiver.receive(ControlJSON.parse(end.encoded()),now:2) {
                if case .saved(let url)=event {saved=url}
                if case .send(let m)=event {receipt=m}
            }
        }
        if saved != nil {break}
    }
    try require(try Data(contentsOf:saved!)==content,"exact streamed file including 10 MB boundary")
    let delivered=try sender.receive(receipt!,now:3)
    if case .delivered=delivered.first {} else {throw FileTransferError.invalid}
    try require(!sender.busy && !receiver.busy,"single file completion state")
}
let small=Data([0,1,2,3]);try small.write(to:sourceURL)
let fixture=try FileSnapshot(source:sourceURL,storage:senderStorage)
var unauthenticatedFile=FileTransfer(authenticated:false)
try mustThrow("untrusted file offer") {_=try unauthenticatedFile.offer(fixture,now:0)}
let fixedOffer=try ControlMessage.make("fileOffer",["name":.string("ok.bin"),"size":.integer(4),"sha256":.string(hashHex(small))])
var receiveGate=FileTransfer(authenticated:true)
_=try receiveGate.receive(fixedOffer,now:0)
let prematureFile=try FileChunk(offerID:fixedOffer.id,offset:0,data:small)
try mustThrow("unapproved binary body") {try receiveGate.receive(prematureFile,now:1)}
let denied=try receiveGate.decide(false,storage:receiverStorage,now:1)
try require(try !denied.boolean("accept") && !receiveGate.busy,"explicit file denial")
try mustThrow("body after denial") {try receiveGate.receive(prematureFile,now:2)}
try mustThrow("file offer replay") {_=try receiveGate.receive(fixedOffer,now:3)}
var partial=FileTransfer(authenticated:true)
_=try partial.receive(fixedOffer,now:0);_=try partial.decide(true,storage:receiverStorage,now:1)
try partial.receive(try FileChunk(offerID:fixedOffer.id,offset:0,data:small.prefix(2)),now:2)
try mustThrow("out of order offset") {try partial.receive(prematureFile,now:3)}
try require(partial.expired(now:17),"file idle timeout")
partial.cancel();try require(!partial.busy,"disconnect clears pending file state")
for limit in fileVectors["limits"] as! [[String:Any]] {
    let size=limit["size"] as! Int
    let offer=try ControlMessage.make("fileOffer",["name":.string("ok.bin"),"size":.integer(size),"sha256":.string(hashHex(small))])
    var receiver=FileTransfer(authenticated:true);var allowed=true
    do {_=try receiver.receive(offer,now:0)} catch {allowed=false}
    try require(allowed==limit["allowed"] as! Bool,"10 MB active profile limits")
}
let faultStorage=try newStorage("fault")
for test in ["hash","size","quota","collision","symlink"] {
    let sink=try IncomingFile(storage:faultStorage,size:4,sha256:test=="hash" ? String(repeating:"0",count:64):hashHex(small),writeBudget:test=="quota" ? 2:4)
    let finalName="received-"+UUID().uuidString.lowercased()+".bin"
    let target=faultStorage.directory.appendingPathComponent(finalName)
    if test=="collision" {try Data([99]).write(to:target)}
    if test=="symlink" {try FileManager.default.createSymbolicLink(at:target,withDestinationURL:sourceURL)}
    if test=="quota" {
        do {try sink.append(offset:0,data:small);throw FlowError.invalidFrame}
        catch FileTransferError.storage(let code) {try require(code==ENOSPC,"injected quota reports ENOSPC")}
    }
    else {
        try sink.append(offset:0,data:test=="size" ? Data(small.prefix(2)):small)
        try mustThrow("safe publication failure: "+test) {_=try sink.finish(finalName:finalName)}
    }
    sink.abort()
    if test=="collision" {try require(try Data(contentsOf:target)==Data([99]),"never overwrite collision")}
    if test=="symlink" {try require(try Data(contentsOf:sourceURL)==small,"symlink cannot overwrite target")}
}
let symlinkSource=fileTestDirectory.appendingPathComponent("source-link")
try FileManager.default.createSymbolicLink(at:symlinkSource,withDestinationURL:sourceURL)
try mustThrow("source symlink rejected") {_=try FileSnapshot(source:symlinkSource,storage:senderStorage)}
let symlinkRoot=fileTestDirectory.appendingPathComponent("directory-link")
try FileManager.default.createSymbolicLink(at:symlinkRoot,withDestinationURL:receiverStorage.directory)
try mustThrow("storage symlink rejected") {_=try TransferStorage(directory:symlinkRoot)}
let orphans=try newStorage("orphans")
let orphan=orphans.directory.appendingPathComponent(".hf-stage-"+UUID().uuidString.lowercased()+".part")
try small.write(to:orphan);try orphans.recoverOrphans()
try require(!FileManager.default.fileExists(atPath:orphan.path),"force-kill orphan cleanup on next launch")
try await MainActor.run {
    let model=AppleDiagnosticModel(store:NoKeychainStore())
    model.setActive(true);model.awaitingApproval=true;model.awaitingFileApproval=true;model.pendingSummary="pending";model.fileConsent="pending";model.receivedText="sensitive";model.draft="draft";model.connected=true;model.fileBusy=true
    model.setActive(false)
    try require(!model.awaitingApproval && !model.awaitingFileApproval && !model.fileBusy && !model.connected && model.receivedText.isEmpty && model.draft.isEmpty && model.fileConsent.isEmpty && model.pendingSummary.isEmpty,"inactive closes text/file approvals and sensitive displays")
    model.setActive(true)
    try require(!model.connected && !model.busy,"foreground never auto-resumes transfer")
}
print("PASS: file framing vectors; streaming 0/1/32KiB/65539/10MB round trips; consent/replay/offset/hash/size/quota/collision/symlink/cancel/orphan/lifecycle failures")

try mustThrow("symlink in storage parent rejected") {_=try TransferStorage(directory:symlinkRoot.appendingPathComponent("must-not-create"))}
try require(!FileManager.default.fileExists(atPath:receiverStorage.directory.appendingPathComponent("must-not-create").path),"never write through parent symlink")
let interruptedSink=try IncomingFile(storage:faultStorage,size:4,sha256:hashHex(small))
try interruptedSink.append(offset:0,data:Data(small.prefix(2)));interruptedSink.abort()
try mustThrow("write after disconnect rejected") {try interruptedSink.append(offset:2,data:Data(small.suffix(2)))}
try require(!(try faultStorage.verifiedFiles()).contains {$0.lastPathComponent.hasPrefix(".hf-stage-")},"partial files never exposed")
let otherKey=SecKeyCreateRandomKey([kSecAttrKeyType:kSecAttrKeyTypeECSECPrimeRandom,kSecAttrKeySizeInBits:256] as CFDictionary,nil)!
let otherCertificate=try LocalCertificate.issue(for:otherKey)
try require(!PeerPin.verifyCertificate(otherCertificate,pin:ephemeralPin),"different identity certificate rejected")
try require(SecCertificateCreateWithData(nil,Data([1,2,3,4]) as CFData)==nil,"malformed DER rejected by OS")
print("PASS: parent symlink confinement, interrupted storage, different-key and malformed-certificate failures")

let uiFixtureStorage=try newStorage("ui-fixture")
try await MainActor.run {
    let model=AppleDiagnosticModel(store:NoKeychainStore(),files:uiFixtureStorage)
    model.setActive(true);model.stageDiagnosticFile()
    try require(model.preparedFile,"actual diagnostic fixture preparation succeeds")
    let staged=try FileManager.default.contentsOfDirectory(at:uiFixtureStorage.directory,includingPropertiesForKeys:nil)
    try require(staged.count==1,"one immutable staged fixture")
    let stagedData=try Data(contentsOf:staged[0])
    let expected=fileVectors["fixture"] as! [String:Any]
    try require(stagedData.count==expected["size"] as! Int && hashHex(stagedData)==expected["sha256"] as! String,"UI fixture matches shared SHA-256 vector")
    model.setActive(false)
    try require(!model.preparedFile && model.fileSummary.isEmpty,"inactive deletes staged outgoing snapshot")
}
let remainingFixtureFiles=try FileManager.default.contentsOfDirectory(atPath:uiFixtureStorage.directory.path)
try require(remainingFixtureFiles.isEmpty,"UI fixture and snapshot cleanup")
print("PASS: actual diagnostic file preparation and inactive staging cleanup with injected private test storage")

// The production anchor API allows OS-managed ancestors, but rejects a linked anchor or receive leaf.
let appBase=fileTestDirectory.appendingPathComponent("app-base",isDirectory:true)
try FileManager.default.createDirectory(at:appBase,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
let anchored=try TransferStorage(appSupportDirectory:appBase)
let anchorFixture=try FileSnapshot.diagnostic(storage:anchored)
try require(anchorFixture.size==262144,"app-container anchor supports protected staging")
let aliasParent=fileTestDirectory.appendingPathComponent("system-parent-alias")
try FileManager.default.createSymbolicLink(at:aliasParent,withDestinationURL:fileTestDirectory)
let aliasAnchor=try TransferStorage(appSupportDirectory:aliasParent.appendingPathComponent("app-base"))
try require(try aliasAnchor.verifiedFiles().isEmpty,"OS-managed ancestor alias accepted at trusted anchor")
try mustThrow("linked app anchor rejected") {_=try TransferStorage(appSupportDirectory:symlinkRoot)}
let linkedBase=fileTestDirectory.appendingPathComponent("linked-base",isDirectory:true)
try FileManager.default.createDirectory(at:linkedBase,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
try FileManager.default.createSymbolicLink(at:linkedBase.appendingPathComponent("HinanaFlowTransfers"),withDestinationURL:receiverStorage.directory)
try mustThrow("linked receive leaf under app anchor rejected") {_=try TransferStorage(appSupportDirectory:linkedBase)}
print("PASS: trusted app-container anchor, system ancestor alias, linked anchor/receive leaf rejection")

let sharingVectors=try JSONSerialization.jsonObject(with:Data(contentsOf:root.appendingPathComponent("protocol/file-sharing-vectors.json"))) as! [String:Any]
for vector in sharingVectors["control"] as! [[String:Any]] {
    var accepted=true
    do {_=try ControlJSON.parse(Data((vector["json"] as! String).utf8))} catch {accepted=false}
    try require(accepted==vector["valid"] as! Bool,"Unicode shared vector "+(vector["name"] as! String))
}
try require(try SharedFilename.normalize("e\u{301}.txt").utf8.elementsEqual("é.txt".utf8),"sender NFC normalization")
let sharingStore=try newStorage("sharing")
let sharingPayload=Data([1,2,3,4])
for name in ["여행 사진.jpg","会議資料.pdf"] {
    let sink=try IncomingFile(storage:sharingStore,size:4,sha256:hashHex(sharingPayload))
    try sink.append(offset:0,data:sharingPayload)
    _=try sink.finish(finalName:"received-"+UUID().uuidString.lowercased()+".bin",displayName:name)
}
let records=try sharingStore.receivedFiles()
try require(records.count==2,"metadata committed for two verified files")
for record in records {
    try require(try sharingStore.export(record)==sharingPayload,"verified named export exact bytes")
    try require(FileManager.default.fileExists(atPath:record.url.path),"export preserves internal original")
}
let changed=records[0];try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:changed.url.path)
try Data([9,9,9,9]).write(to:changed.url)
try mustThrow("export refuses modified file") {_=try sharingStore.export(changed)}
let unsafeExport=records[1]
try FileManager.default.removeItem(at:unsafeExport.url)
try FileManager.default.createSymbolicLink(at:unsafeExport.url,withDestinationURL:sourceURL)
try mustThrow("export refuses changed symlink") {_=try sharingStore.export(unsafeExport)}
for size in [9_999_999,10_000_000,10_000_001] {
    let boundary=fileTestDirectory.appendingPathComponent("경계.bin")
    try Data(repeating:1,count:size).write(to:boundary)
    var accepted=true
    do {let snap=try FileSnapshot(source:boundary,storage:sharingStore);try require(snap.size==size,"exact file boundary")} catch {accepted=false}
    try require(accepted==(size<=10_000_000),"actual selected-file size cap")
}
let interruptedStore=try newStorage("interrupted-sharing")
let aborted=try IncomingFile(storage:interruptedStore,size:4,sha256:hashHex(sharingPayload))
try aborted.append(offset:0,data:sharingPayload.prefix(2));aborted.abort()
try require(try interruptedStore.receivedFiles().isEmpty,"interrupted file absent from completed list")
let orphanMeta=interruptedStore.directory.appendingPathComponent("received-"+UUID().uuidString.lowercased()+".bin.json")
try Data([1]).write(to:orphanMeta)
let untouched=interruptedStore.directory.appendingPathComponent("user-document.txt")
try sharingPayload.write(to:untouched)
try interruptedStore.recoverOrphans()
try require(!FileManager.default.fileExists(atPath:orphanMeta.path),"metadata-only incomplete commit removed")
try require(try Data(contentsOf:untouched)==sharingPayload,"cleanup never deletes unrelated user data")
print("PASS: Unicode sharing vectors, named verified export, unchanged originals, tamper/link rejection, exact 9999999/10000000/10000001 boundaries, interrupted-list and own-only cleanup")

let cancelStore=try newStorage("cancel-wire")
let cancelSnapshot=try FileSnapshot.diagnostic(storage:senderStorage)
var cancelSender=FileTransfer(authenticated:true),cancelReceiver=FileTransfer(authenticated:true)
let cancelOffer=try cancelSender.offer(cancelSnapshot,now:0)
_=try cancelReceiver.receive(cancelOffer,now:0)
let cancelDecision=try cancelReceiver.decide(true,storage:cancelStore,now:1)
_=try cancelSender.receive(cancelDecision,now:1)
if case .chunk(let chunk)=try cancelSender.next(now:2) {try cancelReceiver.receive(chunk,now:2)} else {throw FileTransferError.invalid}
try require(try cancelStore.receivedFiles().isEmpty,"wire partial has no completed metadata pair")
cancelReceiver.cancel();cancelSender.cancel()
try require(try cancelStore.receivedFiles().isEmpty,"wire disconnect/cancel never publishes partial")
try require(try FileManager.default.contentsOfDirectory(at:cancelStore.directory,includingPropertiesForKeys:nil).isEmpty,"wire cancellation removes owned incoming stage")
print("PASS: accepted partial wire transfer cancellation removes stage and completed-list entry")

let bonjourVectors=try JSONSerialization.jsonObject(with:Data(contentsOf:root.appendingPathComponent("protocol/bonjour-vectors.json"))) as! [String:Any]
for v in bonjourVectors["services"] as! [[String:Any]] {
    try require(BonjourLAN.validService(name:v["name"] as! String,type:v["type"] as! String,domain:v["domain"] as! String)==v["valid"] as! Bool,"local service boundary")
}
for v in bonjourVectors["hosts"] as! [[String:Any]] {try require(BonjourLAN.localHost(v["host"] as! String)==v["valid"] as! Bool,"mDNS-only host boundary")}
func numericBytes(_ text:String)->Data {IPv4Address(text)?.rawValue ?? IPv6Address(text)!.rawValue}
for v in bonjourVectors["routes"] as! [[String:Any]] {
    try require(BonjourLAN.onLink(local:numericBytes(v["local"] as! String),peer:numericBytes(v["peer"] as! String),mask:numericBytes(v["mask"] as! String))==v["valid"] as! Bool,"IPv4/IPv6 on-link rule")
}
var catalogue=BonjourCatalog()
let advertised=BonjourCatalog.Advertisement(name:"same name",type:BonjourLAN.serviceType,domain:"local.",interfaceIndex:4)
let sameNameOtherInterface=BonjourCatalog.Advertisement(name:"same name",type:BonjourLAN.serviceType,domain:"local.",interfaceIndex:5)
catalogue.replace([advertised,sameNameOtherInterface,advertised]);try require(catalogue.entries.count==2,"no label-only merge; exact endpoint duplicate dedup")
let staleID=catalogue.entries[0].id
catalogue.replace([advertised]);try require(catalogue.entries[0].id==staleID,"stable session ID on unchanged re-observation")
catalogue.replace([]);try require(catalogue.entries.isEmpty,"service removal removes stale selection")
catalogue.replace([advertised]);try require(catalogue.entries[0].id != staleID,"rediscovery gets a fresh selection ID")
let many=(0..<300).map {BonjourCatalog.Advertisement(name:"service-\($0)",type:BonjourLAN.serviceType,domain:"local.",interfaceIndex:4)}
catalogue.replace(many);try require(catalogue.entries.count==64,"bounded discovery catalogue")
try require(!BonjourLAN.label("safe\u{202e}\nname").contains("\u{202e}") && !BonjourLAN.label("safe\nname").contains("\n"),"untrusted label control/bidi stripping")
for forgedName in ["same name","신뢰된 기기","Hinana Flow-abc123"] {
    var gate=AuthenticationState();gate.setActive(true)
    try mustThrow("advertisement cannot authorize "+forgedName) {try gate.begin(localPin:Data(repeating:1,count:32),expectedPeer:Data(repeating:2,count:32),storedPeer:nil,oobConfirmed:false)}
    try require(!gate.maySendApplicationData,"discovery never enables data")
    var pinned=AuthenticationState();pinned.setActive(true)
    try pinned.begin(localPin:Data(repeating:1,count:32),expectedPeer:Data(repeating:2,count:32),storedPeer:Data(repeating:2,count:32),oobConfirmed:false)
    try mustThrow("same name wrong actual TLS key") {try pinned.nativeTLSReady(TLSPeerEvidence(peerPin:Data(repeating:3,count:32),tls13:true,peerCertificateVerified:true,localIdentityPresented:true))}
    try require(!pinned.maySendApplicationData,"forged label cannot reuse saved trust")
}
try require(!PeerPin.verifyCertificate(otherCertificate,pin:ephemeralPin),"native wrong-key certificate remains rejected for discovered peers")
print("PASS: Bonjour service/host/on-link IPv4+IPv6 vectors, duplicate/removal/rediscovery/64-entry bounds, fake-name/OOB/pinned TLS rejection")

var userSend=FileSendIntent()
let selectedFile=UUID(),otherFile=UUID()
try require(!userSend.consume(selection:selectedFile,authenticated:true),"no automatic send without a user action")
userSend.approve(selection:selectedFile)
try require(!userSend.consume(selection:selectedFile,authenticated:false),"file intent cannot bypass authentication")
userSend.approve(selection:selectedFile)
try require(!userSend.consume(selection:otherFile,authenticated:true),"file selection replacement invalidates intent")
userSend.approve(selection:selectedFile);userSend.clear()
try require(!userSend.consume(selection:selectedFile,authenticated:true),"inactive/cancel clears send intent")
userSend.approve(selection:selectedFile)
try require(userSend.consume(selection:selectedFile,authenticated:true),"explicit selected-file intent after authentication")
try require(!userSend.consume(selection:selectedFile,authenticated:true),"send intent consumed once")
try await MainActor.run {
    let store=NoKeychainStore();let model=AppleDiagnosticModel(store:store)
    model.advertiseBonjour()
    try require(store.calls==0 && !model.isAdvertising && !model.connected && !model.busy,"inactive receiver opens no store or listener")
    model.setActive(true);model.advertiseBonjour()
    try require(store.calls==0 && !model.isAdvertising && !model.busy,"identity required before either platform advertises")
    model.prepare();try require(!model.pairingConfigured && !model.hasStoredTrust,"failing identity cannot imply trust in everyday UI")
    model.setActive(false);model.setActive(true)
    try require(!model.isAdvertising && !model.discovery.browsing && !model.connected,"foreground does not auto-advertise/browse/connect")
}
print("PASS: one-shot selected-file send intent authentication/replacement/cancel guards and foreground receiver startup gates")

// Pure isolation checks: never open OS Keychain in automated tests.
try require(ValidationProfile.production.identityLabel != ValidationProfile.releaseCandidate.identityLabel,"RC identity isolation")
try require(ValidationProfile.production.trustService != ValidationProfile.releaseCandidate.trustService,"RC trust isolation")
try require(ValidationProfile.production.transferDirectory != ValidationProfile.releaseCandidate.transferDirectory,"RC storage isolation")
print("PASS RC identity/trust/storage namespace isolation (no Keychain access)")

let isolated=try TransferStorage(appSupportDirectory:appBase,profile:.releaseCandidate)
let productionStage=anchored.directory.appendingPathComponent(".hf-stage-"+UUID().uuidString.lowercased()+".part")
let rcStage=isolated.directory.appendingPathComponent(".hf-stage-"+UUID().uuidString.lowercased()+".part")
try Data([1]).write(to:productionStage);try Data([2]).write(to:rcStage)
try isolated.recoverOrphans()
try require(FileManager.default.fileExists(atPath:productionStage.path),"RC recovery must preserve production stage")
try require(!FileManager.default.fileExists(atPath:rcStage.path),"RC recovery removes only RC stage")
print("PASS RC orphan recovery cannot enter production storage")

for other in [ValidationProfile.production,.releaseCandidate] {
    try require(ValidationProfile.androidInterop.identityLabel != other.identityLabel,"Android test identity isolation")
    try require(ValidationProfile.androidInterop.trustService != other.trustService,"Android test trust isolation")
    try require(ValidationProfile.androidInterop.transferDirectory != other.transferDirectory,"Android test file isolation")
}
print("PASS Android interoperability profile never reuses production/RC namespace")
