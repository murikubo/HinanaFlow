import Foundation
import Combine
import Network
import Security
import FlowCore
#if os(iOS)
import UIKit
#endif

private enum SetupFailure:String,Error {case inactive,identity,port,fingerprint,selfPeer,lan}

@MainActor public final class AppleDiagnosticModel: ObservableObject {
    public let profile:ValidationProfile
    public let discovery=BonjourDiscovery()
    @Published public private(set) var hasStoredTrust=false
    @Published public private(set) var isAdvertising=false
    @Published public var userNotice=""
    private var stagedSelectionID:UUID?
    private var sendIntent=FileSendIntent()
    @Published public var bonjourStatus="Bonjour 중지됨"
    private var pathMonitor:NWPathMonitor?
    private var routeInterface:NWInterface?
    private var routeSignature:Set<String>?
    private var bonjourMode=false
    @Published public var status = "중지됨"
    @Published public var fingerprint = ""
    @Published public var local = ""
    @Published public var peer = ""
    @Published public var port = "45731"
    @Published public var expectedFingerprint = ""
    @Published public var confirmedOOB = false
    @Published public var connected = false
    @Published public var busy = false
    @Published public var awaitingApproval = false
    @Published public var pendingSummary = ""
    @Published public var receivedText = ""
    @Published public var draft = ""
    @Published public var canSend = false
    @Published public var fileSummary=""
    @Published public var fileConsent=""
    @Published public var awaitingFileApproval=false
    @Published public var fileBusy=false
    @Published public var preparedFile=false
    @Published public var savedFiles:[ReceivedFile]=[]
    private var storage:TransferStorage?
    private var snapshot:FileSnapshot?
    private var fileState=FileTransfer(authenticated:false)
    private var filePumping=false
    private let store:any AppleIdentityStore
    private var authorization=AuthenticationState()
    private var audit:TLSHandshakeAudit?
    public init(store:(any AppleIdentityStore)? = nil,files:TransferStorage? = nil,profile:ValidationProfile = .production) {self.profile=profile;self.store=store ?? PlatformIdentityStore.make(profile:profile);self.storage=files;discovery.onInvalidated={[weak self] in self?.stop("서비스 소멸·탐색 종료 — 연결 종료됨")}}
    public func setActive(_ active:Bool) {
        authorization.setActive(active)
        if !active {stop("앱 비활성 — 연결 종료됨")}
    }
    private var identity: SecIdentity?
    private var localPin = Data()
    private var peerPin = Data()
    private var hadTrust = false
    private var approvedOOB = false
    private var connection: NWConnection?
    private var listener: NWListener?
    private var ticker: Task<Void,Never>?
    private var protocolState = TextProtocol(authenticated:false)
    private var decoder = TransferDecoder()
    private var frameDeadline: Double?
    private var started = 0.0
    private var activeSince = 0.0
    private var lastActivity = 0.0
    private var pendingWrites = 0
    private var token = UUID()
    private var now: Double { ProcessInfo.processInfo.systemUptime }
    private var isActiveNow:Bool {
        #if os(iOS)
        return authorization.active && UIApplication.shared.applicationState == .active
        #else
        return authorization.active
        #endif
    }
    public func prepare() {
        guard isActiveNow,!busy else {return}
        do {
            let identity = try store.loadOrCreate()
            localPin = try IdentityPin.digest(of:identity); self.identity = identity
            fingerprint = localPin.map { String(format:"%02x",$0) }.joined()
            if local.isEmpty { local = LANBinding.interfaces().first?.address ?? "" }
            if let saved = try store.trustedPeer(localPin:localPin) {
                hasStoredTrust=true
                expectedFingerprint = saved.map { String(format:"%02x",$0) }.joined()
                status = "저장된 상대 키가 있습니다"
            } else {hasStoredTrust=false;status = "신원 준비됨 — 상대 화면의 전체 지문을 직접 확인하세요"}
            userNotice="기기가 준비됐습니다"
        } catch {
            // Fixed stage names and numeric OS status only; never include key material or error userInfo.
            let code:String
            switch error {
            case IdentityError.store(let value): code="OSStatus \(value)"
            case IdentityError.invalidKeyAttributes(let field): code="HF-I-ATTR-\(field.rawValue)"
            case IdentityError.identityAssociation: code="HF-I-ASSOC"
            default: code="HF-I-INVALID"
            }
            identity=nil;localPin=Data();fingerprint="";hasStoredTrust=false
            status = "신원 저장소 오류 — 연결 차단 (\(code))";userNotice="기기 준비에 실패했습니다. 진단 메뉴에서 오류를 확인하세요"
        }
    }
    private func configureIdentity() throws -> sec_identity_t {
        guard isActiveNow,!busy else {throw SetupFailure.inactive}
        guard let identity,let tlsIdentity=sec_identity_create(identity) else {throw SetupFailure.identity}
        let pin:Data
        do {pin=try PeerFingerprint.parse(expectedFingerprint)} catch {throw SetupFailure.fingerprint}
        guard pin != localPin else {throw SetupFailure.selfPeer}
        let saved=try store.trustedPeer(localPin:localPin)
        if let saved {
            guard saved == pin else { throw IdentityError.keyChanged }; hadTrust=true
        } else { guard confirmedOOB else { throw IdentityError.oobRequired }; hadTrust=false }
        try authorization.begin(localPin:localPin,expectedPeer:pin,storedPeer:saved,oobConfirmed:confirmedOOB)
        approvedOOB=confirmedOOB; peerPin=pin
        return tlsIdentity
    }
    private func configure() throws -> (LANBinding,sec_identity_t) {
        let identity=try configureIdentity()
        guard let port=UInt16(port),port>=1024 else {throw SetupFailure.port}
        do {return (try LANBinding(local:local,peer:peer,port:port),identity)} catch {throw SetupFailure.lan}
    }
    public func start(listen: Bool) {
        do {
            let (binding, identity) = try configure()
            discovery.stop();pathMonitor?.cancel();pathMonitor=nil;routeSignature=nil
            token=UUID(); let generation=token; busy=true; started=now; lastActivity=now
            status = listen ? "최대 60초간 TLS 연결 대기" : "TLS 상호 인증 중"
            if listen {
                let (next,evidence)=try PinnedTLS.authenticatedListener(binding,pin:peerPin,identity:identity); audit=evidence; listener=next
                next.newConnectionHandler = { [weak self] candidate in
                    Task { @MainActor in
                        guard let self, self.token==generation, self.connection==nil else { candidate.cancel(); return }
                        guard LANBinding.peerMatches(candidate.endpoint,expected:binding.peer) else { candidate.cancel(); return }
                        self.listener?.cancel(); self.listener=nil; self.attach(candidate,generation:generation)
                    }
                }
                next.stateUpdateHandler = { [weak self] state in
                    if case .failed = state { Task { @MainActor in if self?.token==generation { self?.stop("TLS 수신 시작 실패") } } }
                }
                next.start(queue:.main)
            } else {
                let (next,evidence)=try PinnedTLS.authenticatedConnection(binding,pin:peerPin,identity:identity)
                audit=evidence;attach(next,generation:generation)
            }
            ticker=Task { [weak self] in
                while !Task.isCancelled {
                    try? await Task.sleep(for:.seconds(1))
                    guard !Task.isCancelled, let self, self.token==generation else { return }
                    if self.connected {
                        if self.now-self.activeSince >= 600 || self.now-self.lastActivity >= 90 || self.protocolState.expired(now:self.now) || self.fileState.expired(now:self.now) || (self.frameDeadline.map { self.now >= $0 } ?? false) {
                            self.stop("시간 제한으로 종료됨"); return
                        }
                    } else if self.now-self.started >= (listen && self.connection==nil ? 60 : 10) {
                        self.stop("TLS 인증 시간 초과"); return
                    }
                }
            }
        } catch {
            let message:String
            switch error {
            case SetupFailure.inactive:message="HF-S-ACTIVE: 앱 활성 상태에서 다시 시도하세요"
            case SetupFailure.identity:message="HF-S-IDENTITY: 먼저 신원을 불러오세요"
            case SetupFailure.port:message="HF-S-PORT: 포트는 1024..65535여야 합니다"
            case SetupFailure.fingerprint:message="HF-S-PIN: 상대 지문 64자리를 확인하세요"
            case SetupFailure.selfPeer:message="HF-S-SELF: 내 지문 대신 상대 지문을 입력하세요"
            case SetupFailure.lan:message="HF-S-LAN: 내/상대 IPv4 역할과 동일 subnet을 확인하세요"
            case IdentityError.keyChanged:message="HF-S-CHANGED: 저장된 상대 키와 다릅니다 — 재확인 필요"
            case IdentityError.oobRequired:message="HF-S-OOB: 최초 신뢰는 상대 화면 전체 지문 확인이 필요합니다"
            default:message="HF-S-STORE: 신원·신뢰 저장소 검증 실패"
            }
            stop("연결 차단 — "+message)
        }
    }
    private func monitorLAN(generation:UUID,initial:@escaping @MainActor @Sendable (NWInterface)->Void) {
        let monitor=NWPathMonitor();pathMonitor=monitor
        monitor.pathUpdateHandler = {[weak self] path in
            Task {@MainActor in
                guard let self,self.token==generation else {return}
                let signature=BonjourLAN.pathSignature(path.availableInterfaces)
                guard path.status == .satisfied,!signature.isEmpty else {self.stop("LAN 경로 없음 — 수동 재시작 필요");return}
                if let old=self.routeSignature {
                    if old != signature {self.stop("LAN 주소/네트워크 변경 — 다시 탐색하세요")}
                } else {
                    guard let interface=path.availableInterfaces.first(where:{ candidate in [.wifi,.wiredEthernet].contains(candidate.type) && BonjourLAN.addresses().contains(where:{$0.index==UInt32(candidate.index)})}) else {self.stop();return}
                    self.routeSignature=signature;initial(interface)
                }
            }
        }
        monitor.start(queue:.main)
    }
    private func bonjourDeadline(generation:UUID,waiting:Bool) {
        ticker=Task {[weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for:.seconds(1))
                guard !Task.isCancelled,let self,self.token==generation else {return}
                if self.connected {
                    if self.now-self.activeSince>=600 || self.now-self.lastActivity>=90 || self.protocolState.expired(now:self.now) || self.fileState.expired(now:self.now) || (self.frameDeadline.map {self.now >= $0} ?? false) {self.stop("시간 제한으로 종료됨");return}
                } else if self.now-self.started >= (waiting && self.connection==nil ? 60:10) {self.stop("Bonjour/TLS 시간 초과");return}
            }
        }
    }
    public func advertiseBonjour() {
        do {
            let identity=try configureIdentity()
            discovery.stop();pathMonitor?.cancel();routeSignature=nil
            bonjourMode=true;isAdvertising=true;busy=true;token=UUID();let generation=token;started=now
            userNotice="상대 기기의 연결을 기다립니다"
            if snapshot == nil {fileSummary=""}
            bonjourStatus="LAN 준비 중 — 60초 사용자 시작 광고";status="Bonjour TLS 수신 준비 중"
            monitorLAN(generation:generation) {[weak self] interface in
                guard let self,self.token==generation else {return}
                do {
                    self.routeInterface=interface
                    let (next,audit)=try PinnedTLS.bonjourListener(interface:interface,pin:self.peerPin,identity:identity)
                    self.audit=audit;self.listener=next
                    next.service=NWListener.Service(name:"Hinana Flow-"+String(UUID().uuidString.prefix(6)),type:BonjourLAN.serviceType,domain:"local.",txtRecord:nil)
                    next.newConnectionHandler = {[weak self] candidate in Task {@MainActor in
                        guard let self,self.token==generation,self.connection==nil,BonjourLAN.allowed(candidate.endpoint,on:interface) else {candidate.cancel();return}
                        self.attach(candidate,generation:generation)
                    }}
                    next.stateUpdateHandler = {[weak self] state in Task {@MainActor in
                        guard let self,self.token==generation else {return}
                        if case .ready=state {self.bonjourStatus="Bonjour 광고 중 · 키/개인 이름/TXT 없음";self.status="Bonjour 상호 TLS 수신 대기"}
                        if case .failed=state {self.stop("Bonjour 광고 실패 — 수동 입력 사용 가능")}
                    }}
                    next.start(queue:.main)
                } catch {self.stop("Bonjour TLS 수신 준비 실패")}
            }
            bonjourDeadline(generation:generation,waiting:true)
        } catch {stop("Bonjour 차단 — 신원·저장 핀 또는 최초 OOB를 확인하세요")}
    }
    public func browseBonjour() {
        guard isActiveNow,!busy else {return}
        let staged=snapshot,selection=stagedSelectionID
        stop();snapshot=staged;stagedSelectionID=selection;preparedFile=staged != nil
        if let staged {fileSummary="파일 준비됨: \(staged.name) / \(staged.size) bytes"}
        discovery.start();bonjourStatus="사용자 시작 Bonjour 탐색";userNotice="연결할 기기를 선택하세요"
        let generation=token
        monitorLAN(generation:generation) {_ in}
    }
    public func connectDiscovered(_ id:UUID) {
        do {
            let identity=try configureIdentity()
            bonjourMode=true;busy=true;let generation=token;started=now
            status="로컬 서비스 해석 및 상호 TLS 인증 중"
            discovery.resolve(id) {[weak self] endpoint,interface in
                guard let self,self.token==generation,self.isActiveNow else {return}
                guard let endpoint,let interface else {self.stop("로컬 주소 해석 실패 — 다시 탐색 또는 수동 입력 사용");return}
                do {
                    self.routeInterface=interface
                    let (next,audit)=try PinnedTLS.bonjourConnection(endpoint:endpoint,interface:interface,pin:self.peerPin,identity:identity)
                    self.audit=audit;self.attach(next,generation:generation)
                } catch {self.stop("발견 주소 LAN 검증 실패 — 연결 차단")}
            }
            bonjourDeadline(generation:generation,waiting:false)
        } catch {stop("Bonjour 연결 차단 — 신원·저장 핀 또는 최초 OOB 확인 필요")}
    }
    public var pairingConfigured:Bool {
        guard !fingerprint.isEmpty else {return false}
        if hasStoredTrust {return true}
        return confirmedOOB && (try? PeerFingerprint.parse(expectedFingerprint)) != nil && expectedFingerprint.lowercased() != fingerprint
    }
    /// Called only by an explicit connect/send button; no discovery callback can authorize a send.
    public func connectChosen(_ peer:DiscoveredPeer,sendPreparedFile:Bool) {
        do {
            guard !sendPreparedFile || (snapshot != nil && stagedSelectionID != nil) else {throw FlowError.untrusted}
            let identity=try configureIdentity()
            discovery.stop();pathMonitor?.cancel();pathMonitor=nil;routeSignature=nil
            bonjourMode=true;busy=true;token=UUID();let generation=token;started=now
            sendIntent.clear()
            if sendPreparedFile,let selection=stagedSelectionID {sendIntent.approve(selection:selection)}
            status="선택한 기기 주소·상호 TLS 확인 중";userNotice="상대 기기를 확인하고 있습니다"
            monitorLAN(generation:generation) {[weak self] _ in
                guard let self,self.token==generation else {return}
                self.discovery.resolveRemembered(peer) {[weak self] endpoint,interface in
                    guard let self,self.token==generation,self.isActiveNow else {return}
                    guard let endpoint,let interface else {self.stop("선택 기기 소멸 또는 주소 해석 실패");return}
                    do {
                        self.routeInterface=interface
                        let (next,audit)=try PinnedTLS.bonjourConnection(endpoint:endpoint,interface:interface,pin:self.peerPin,identity:identity)
                        self.audit=audit;self.attach(next,generation:generation)
                    } catch {self.stop("선택한 기기 LAN 검증 실패")}
                }
            }
            bonjourDeadline(generation:generation,waiting:false)
        } catch {stop("선택 기기 연결 차단 — 신원·저장 핀·OOB 또는 파일 준비 확인")}
    }
    private func attach(_ next: NWConnection, generation: UUID) {
        connection=next; started=now
        next.stateUpdateHandler = { [weak self] state in
            Task { @MainActor in
                guard let self, self.token==generation else { return }
                switch state {
                case .ready:
                    guard !self.connected else { return }
                    guard self.isActiveNow else {self.stop("앱 비활성 — 연결 종료됨");return}
                    do {
                        if self.bonjourMode {
                            guard let interface=self.routeInterface,let endpoint=next.currentPath?.remoteEndpoint,
                                  BonjourLAN.allowed(endpoint,on:interface) else {throw FlowError.invalidAddress}
                        }
                        guard let audit=self.audit else {throw FlowError.untrusted}
                        try self.authorization.nativeTLSReady(audit.evidence(for:next))
                        try self.store.confirm(localPin:self.localPin,peerPin:self.peerPin,oobConfirmed:self.hadTrust || self.approvedOOB,mutualTLS:self.authorization.phase == .verified)
                        try self.authorization.trustPersisted()
                        if self.bonjourMode {self.discovery.authenticated();self.bonjourStatus="신뢰된 현재 TLS 기기 — 실제 상대 키 검증 완료"}
                        self.hasStoredTrust=true;self.userNotice="기기 확인이 완료됐습니다"
                        self.connected=true; self.canSend=true; self.activeSince=self.now; self.lastActivity=self.now
                        self.fileState=FileTransfer(authenticated:self.authorization.maySendApplicationData)
                        self.protocolState=TextProtocol(authenticated:self.authorization.maySendApplicationData); self.status="상호 TLS 1.3 인증됨 · 텍스트 수신은 건별 승인 필요"
                        self.read(generation:generation)
                        if self.sendIntent.consume(selection:self.stagedSelectionID,authenticated:self.authorization.maySendApplicationData) {self.offerFile()}
                    } catch { self.stop("신뢰 저장 실패 — 연결 종료") }
                case .failed: self.stop("TLS 인증 또는 연결 실패")
                case .cancelled: self.stop("연결 종료됨")
                default: break
                }
            }
        }
        next.start(queue:.main)
    }
    private func read(generation: UUID) {
        connection?.receive(minimumIncompleteLength:1,maximumLength:4096) { [weak self] data,_,complete,error in
            Task { @MainActor in
                guard let self, self.token==generation else {return}
                guard self.isActiveNow,self.authorization.maySendApplicationData,self.connected else {
                    self.stop("앱 비활성 또는 미인증 — 연결 종료됨");return
                }
                do {
                    if let data, !data.isEmpty {
                        if self.frameDeadline==nil { self.frameDeadline=self.now+10 }
                        let frames=try self.decoder.feed(data)
                        if !self.decoder.hasPartialFrame { self.frameDeadline=nil }
                        else if !frames.isEmpty { self.frameDeadline=self.now+10 }
                        for frame in frames {
                            switch frame {
                            case .chunk(let chunk):
                                try self.fileState.receive(chunk,now:self.now)
                            case .control(let bytes):
                                let message=try ControlJSON.parse(bytes)
                                if message.type.hasPrefix("file") {
                                    let events=try self.fileState.receive(message,now:self.now)
                                    for event in events {
                                        switch event {
                                        case .send(let m):try self.write(m,generation:generation)
                                        case .consent(let name,let size):self.awaitingFileApproval=true;self.fileConsent="파일 제안: \(name) / \(size) bytes"
                                        case .startSending:self.pumpFile(generation:generation)
                                        case .saved: self.awaitingFileApproval=false;self.fileConsent="";self.fileSummary="크기·SHA-256 검증 및 저장 완료";self.refreshFiles()
                                        case .delivered:self.fileSummary="상대 파일 검증·저장 확인 완료"
                                        case .denied:self.awaitingFileApproval=false;self.fileConsent="";self.fileSummary="파일 제안 거절 또는 취소됨"
                                        }
                                    }
                                } else {
                                    let events=try self.protocolState.receive(message,now:self.now)
                                    for event in events {
                                        switch event {
                                        case .send(let m): try self.write(m,generation:generation)
                                        case .consent(_,let bytes,let scalars): self.awaitingApproval=true; self.pendingSummary="텍스트 수신 제안: \(scalars)자 / \(bytes) bytes"
                                        case .received(let text): self.receivedText=text; self.awaitingApproval=false; self.pendingSummary="수신 완료"
                                        case .delivered: self.status="상대 수신 확인 완료"
                                        case .denied: self.status="텍스트 제안이 거부 또는 취소됨"; self.awaitingApproval=self.protocolState.needsConsent
                                        }
                                    }
                                }
                            }
                            self.lastActivity=self.now;self.fileBusy=self.fileState.busy
                        }
                        self.canSend = !self.protocolState.hasOutgoing
                    }
                    if error != nil || complete { self.stop("연결 종료됨"); return }
                    self.read(generation:generation)
                } catch { self.stop("프로토콜 검증 실패 — 연결 종료") }
            }
        }
    }
    private func write(_ message: ControlMessage, generation: UUID) throws {
        guard isActiveNow else {stop("앱 비활성 — 연결 종료됨");throw FlowError.untrusted}
        try authorization.requireApplicationData()
        guard connected, let connection, pendingWrites < 8 else { throw FlowError.untrusted }
        pendingWrites += 1; lastActivity=now
        let frame=try ControlDecoder.encode(message.encoded())
        connection.send(content:frame,completion:.contentProcessed { [weak self] error in
            Task { @MainActor in
                guard let self, self.token==generation else { return }
                self.pendingWrites -= 1
                if error != nil { self.stop("전송 오류 — 연결 종료") }
            }
        })
    }
    public func send() {
        do { let m=try protocolState.offer(text:draft,now:now); try write(m,generation:token); draft=""; canSend=false; status="본문 전송 전 상대 승인 대기" }
        catch { stop("텍스트 제안 실패 — 연결 종료") }
    }
    public func decide(_ accept: Bool) {
        do { let m=try protocolState.decide(accept:accept,now:now); try write(m,generation:token); awaitingApproval=false; pendingSummary=accept ? "본문 수신 대기" : "수신 거부됨" }
        catch { stop("수신 승인 실패 — 연결 종료") }
    }
    private func fileErrorCode(_ error:Error) -> String {
        // Fixed stages and numeric codes only. No paths, names, contents, or localized error payloads.
        switch error {
        case let failure as FileStorageSetupError:return "HF-F-"+failure.stage.rawValue+"-"+String(failure.code)
        case FileTransferError.storage(let code):return "HF-F-IO-"+String(code)
        case FileTransferError.expired:return "HF-F-TIME"
        case FileTransferError.integrity:return "HF-F-HASH"
        case FileTransferError.invalid:return "HF-F-STATE"
        default:return "HF-F-OS-"+String((error as NSError).code)
        }
    }
    private func fileStorage() throws -> TransferStorage {
        if let storage {return storage}
        let base=try FileManager.default.url(for:.applicationSupportDirectory,in:.userDomainMask,appropriateFor:nil,create:true)
        let store=try TransferStorage(appSupportDirectory:base,profile:profile)
        try store.recoverOrphans();storage=store;return store
    }
    public func refreshFiles() {
        guard isActiveNow else {return}
        do {savedFiles=try fileStorage().receivedFiles()}
        catch {fileSummary="저장소 접근 실패 (\(fileErrorCode(error)))"}
    }
    public func prepareExport(_ file:ReceivedFile) -> Data? {
        guard isActiveNow,!busy else {return nil}
        do {return try fileStorage().export(file)}
        catch {fileSummary="내보내기 검증 실패 (\(fileErrorCode(error)))";return nil}
    }
    public func exportCompleted(_ success:Bool) {fileSummary=success ? "사용자 지정 위치로 내보내기 완료":"내보내기 취소 또는 실패 — 내부 원본 유지"}
    public func stageFile(_ url:URL) {
        guard isActiveNow,!busy else {return}
        let scoped=url.startAccessingSecurityScopedResource();defer {if scoped {url.stopAccessingSecurityScopedResource()}}
        do {let staged=try FileSnapshot(source:url,storage:fileStorage());snapshot=staged;stagedSelectionID=UUID();sendIntent.clear();preparedFile=true;fileSummary="파일 준비됨: \(staged.name) / \(staged.size) bytes";userNotice="파일이 준비됐습니다"}
        catch {snapshot=nil;stagedSelectionID=nil;sendIntent.clear();preparedFile=false;userNotice="파일을 준비할 수 없습니다";fileSummary="파일 준비 실패: 일반 파일·안전한 파일명·10 MB 한도를 확인하세요"}
    }
    public func stageDiagnosticFile() {
        guard isActiveNow,!busy else {return}
        do {
            snapshot=try FileSnapshot.diagnostic(storage:fileStorage());stagedSelectionID=UUID();sendIntent.clear()
            preparedFile=true;fileSummary="공개 테스트 파일 준비됨: 262144 bytes"
        } catch {snapshot=nil;stagedSelectionID=nil;sendIntent.clear();preparedFile=false;fileSummary="테스트 파일 준비 실패 (\(fileErrorCode(error)))"}
    }
    public func offerFile() {
        do {
            guard isActiveNow,connected,let snapshot else {throw FlowError.untrusted}
            try authorization.requireApplicationData()
            let offer=try fileState.offer(snapshot,now:now)
            self.snapshot=nil;stagedSelectionID=nil;sendIntent.clear();preparedFile=false;fileBusy=true
            try write(offer,generation:token);fileSummary="파일 본문 전송 전 상대 승인 대기"
        } catch {stop("파일 제안 실패 — 연결 종료")}
    }
    public func decideFile(_ accept:Bool) {
        do {
            guard isActiveNow,connected else {throw FlowError.untrusted}
            let message=try fileState.decide(accept,storage:fileStorage(),now:now)
            try write(message,generation:token)
            awaitingFileApproval=false;fileConsent="";fileBusy=fileState.busy
            fileSummary=accept ? "승인됨 — 파일 수신·검증 중":"파일 수신 거절됨"
        } catch {stop("파일 수신 준비 실패 (\(fileErrorCode(error))) — 연결 종료")}
    }
    private func pumpFile(generation:UUID) {
        guard !filePumping else {return}
        do {
            guard isActiveNow,connected,let connection,pendingWrites<8 else {throw FlowError.untrusted}
            try authorization.requireApplicationData()
            switch try fileState.next(now:now) {
            case .end(let message):try write(message,generation:generation);fileSummary="파일 본문 송신 완료 — 상대 검증 대기"
            case .chunk(let chunk):
                filePumping=true;pendingWrites+=1;lastActivity=now
                connection.send(content:TransferDecoder.encode(chunk),completion:.contentProcessed { [weak self] error in
                    Task { @MainActor in
                        guard let self,self.token==generation else {return}
                        self.filePumping=false;self.pendingWrites-=1
                        if error != nil {self.stop("파일 전송 오류 — 연결 종료");return}
                        self.pumpFile(generation:generation)
                    }
                })
            }
        } catch {stop("파일 전송 검증 실패 — 연결 종료")}
    }
    public func forget() {
        guard isActiveNow else {return}
        stop("연결 종료됨")
        do { try store.forgetPeer();hasStoredTrust=false; expectedFingerprint=""; confirmedOOB=false; status="상대 신뢰 삭제됨 — 재확인 필요" }
        catch { status="신뢰 삭제 실패" }
    }
    public func stop(_ reason: String = "중지됨") {
        let hadWork=busy || connected || discovery.browsing || snapshot != nil || fileState.busy
        sendIntent.clear();stagedSelectionID=nil;isAdvertising=false
        if reason.hasPrefix("앱 비활성") && !hadWork {userNotice=""}
        else if reason.contains("시간 초과") || reason.contains("시간 제한") {userNotice="대기 시간이 끝났습니다. 다시 받기 대기 또는 주변 기기 찾기를 눌러주세요"}
        else {userNotice=reason=="중지됨" ? "연결이 종료됐습니다":"연결이 종료됐습니다. 필요하면 다시 기기를 선택하세요"}
        discovery.stop();pathMonitor?.cancel();pathMonitor=nil;routeInterface=nil;routeSignature=nil;bonjourMode=false;bonjourStatus="Bonjour 중지됨"
        authorization.close();audit=nil
        token=UUID(); ticker?.cancel(); ticker=nil; listener?.cancel(); listener=nil
        connection?.stateUpdateHandler=nil; connection?.cancel(); connection=nil
        connected=false; busy=false; canSend=false; awaitingApproval=false; pendingWrites=0
        protocolState=TextProtocol(authenticated:false); decoder=TransferDecoder(); frameDeadline=nil
        fileState.cancel();fileState=FileTransfer(authenticated:false);snapshot=nil;preparedFile=false;fileBusy=false;filePumping=false;awaitingFileApproval=false;fileConsent="";fileSummary="";savedFiles=[]
        draft=""; receivedText=""; pendingSummary=""; status=reason
    }
}
