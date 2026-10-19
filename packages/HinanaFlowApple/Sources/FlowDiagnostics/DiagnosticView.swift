import SwiftUI
import UniformTypeIdentifiers
#if os(iOS)
import UIKit
#else
import AppKit
#endif

struct ExportDocument:FileDocument {
    static var readableContentTypes:[UTType] {[.data]}
    let data:Data
    init(data:Data) {self.data=data}
    init(configuration:ReadConfiguration) throws {throw CocoaError(.fileReadUnsupportedScheme)}
    func fileWrapper(configuration:WriteConfiguration) throws -> FileWrapper {FileWrapper(regularFileWithContents:data)}
}

@MainActor public struct AppleDiagnosticView:View {
    @ObservedObject private var discovery:BonjourDiscovery
    @ObservedObject private var model:AppleDiagnosticModel
    @State private var importing=false
    @State private var exporting=false
    @State private var exportDocument:ExportDocument?
    @State private var exportName="received.bin"
    @State private var exportType=UTType.data
    private let manageLifecycle:Bool
    @Environment(\.scenePhase) private var phase
    public init(model:AppleDiagnosticModel,manageLifecycle:Bool=true) {self.model=model;self.discovery=model.discovery;self.manageLifecycle=manageLifecycle}
    public var body:some View {
        ScrollView {
            VStack(alignment:.leading,spacing:14) {
                Text("Hinana Flow · TLS 1.3 진단").font(.title2)
                Text("두 기기에서 상대 화면의 전체 64자리 공개키 지문을 직접 확인하세요. 인증 및 신뢰 저장 전에는 본문을 전송하지 않습니다.")
                Button("신원 생성 또는 불러오기") {model.prepare()}.disabled(model.busy || phase != .active)
                Text("내 공개키 SHA-256 지문").font(.caption)
                Text(model.fingerprint.isEmpty ? "신원 미준비" : model.fingerprint)
                    .font(.system(.caption,design:.monospaced)).textSelection(.enabled)
                    .frame(maxWidth:.infinity,alignment:.leading)
                #if os(iOS)
                Text("신원 키: Secure Enclave P-256 · 내보내기 불가 · 활성 상태에서만 통신").font(.caption)
                #else
                Text("신원 키: Secure Enclave P-256 · 내보내기 불가 · 개발 서명 필요").font(.caption)
                #endif
                Divider()
                Text("Bonjour · 사용자 시작 · 미인증 발견 목록").font(.headline)
                Button("Bonjour 광고 및 TLS 수신 (60초)") {model.advertiseBonjour()}.disabled(model.busy || phase != .active || model.fingerprint.isEmpty)
                Button("Bonjour 기기 탐색 (60초)") {model.browseBonjour()}.disabled(model.busy || phase != .active)
                Text(discovery.status).accessibilityIdentifier("discoveryStatus")
                ForEach(discovery.peers) {peer in
                    VStack(alignment:.leading) {
                        Text("광고 이름 (미신뢰): \(peer.label)")
                        Text("목록 항목 \(peer.id.uuidString.prefix(6)) · \(discovery.authenticatedID==peer.id && model.connected ? "현재 TLS 공개키 검증됨":"미인증 — 이름만으로 신뢰하지 마세요")").font(.caption)
                        Button("이 기기 선택 및 TLS 인증") {model.connectDiscovered(peer.id)}.disabled(model.busy || !discovery.browsing || model.fingerprint.isEmpty)
                    }
                }
                Button("Bonjour/연결 종료") {model.stop()}
                Text(model.bonjourStatus).accessibilityIdentifier("bonjourStatus")
                Text("발견은 신뢰 등록이 아닙니다. 최초에는 상대 화면의 전체 지문을 입력·확인하고, 이후에는 저장된 핀을 TLS에서 검증합니다.").font(.caption)
                Divider()
                Text("수동 IPv4 연결 (자동 발견 실패 시)").font(.headline)
                Group {
                    input("내 LAN IPv4",text:$model.local)
                    input("상대 IPv4 (동일 subnet)",text:$model.peer)
                    input("TCP 포트 (기본 45731)",text:$model.port)
                    input("직접 확인한 상대 지문 (64 hex)",text:$model.expectedFingerprint).onChange(of:model.expectedFingerprint) {_,_ in model.confirmedOOB=false}
                    Toggle("상대 기기 화면에서 전체 지문을 직접 확인했습니다",isOn:$model.confirmedOOB)
                }.disabled(model.busy)
                VStack(alignment:.leading,spacing:10) {
                    Button("TLS 수신 대기 (60초)") {model.start(listen:true)}.disabled(model.busy || model.fingerprint.isEmpty)
                    Button("상대에 TLS 연결") {model.start(listen:false)}.disabled(model.busy || model.fingerprint.isEmpty)
                    Button("연결 종료") {model.stop()}
                    Button("상대 신뢰 삭제 후 재확인") {model.forget()}.disabled(model.fingerprint.isEmpty)
                }
                Text(model.status).font(.callout).accessibilityIdentifier("connectionStatus")
                Text("보낼 텍스트 (최대 8192 Unicode scalar)").font(.caption)
                TextEditor(text:$model.draft).frame(height:100).border(.secondary).disabled(!model.connected)
                Button("이번 텍스트의 전송 제안 승인") {model.send()}
                    .disabled(!model.connected || !model.canSend || model.draft.isEmpty)
                Text(model.pendingSummary)
                VStack(alignment:.leading,spacing:10) {
                    Button("이번 텍스트 수신 승인") {model.decide(true)}.disabled(!model.awaitingApproval)
                    Button("이번 텍스트 수신 거절") {model.decide(false)}.disabled(!model.awaitingApproval)
                }
                Text("승인 후 수신한 본문 (비활성·종료 시 지움)").font(.caption)
                Text(model.receivedText).textSelection(.enabled).frame(maxWidth:.infinity,alignment:.leading)
                    .accessibilityIdentifier("receivedText")
                Divider()
                Text("단일 파일 · 최대 10 MB").font(.headline)
                Text("파일은 연결 전에 준비하세요. 승인 전 본문은 전송하지 않으며, 검증된 파일도 자동으로 열지 않습니다.").font(.caption)
                Button("파일 선택 (연결 전)") {selectFile()}.disabled(model.busy)
                Button("공개 테스트 파일 준비 (256 KiB)") {model.stageDiagnosticFile()}.disabled(model.busy)
                Button("이번 파일 전송 제안") {model.offerFile()}.disabled(!model.connected || !model.preparedFile || model.fileBusy)
                Text(model.fileSummary).accessibilityIdentifier("fileStatus")
                Text(model.fileConsent)
                Button("이번 파일 수신 승인") {model.decideFile(true)}.disabled(!model.awaitingFileApproval)
                Button("이번 파일 수신 거절") {model.decideFile(false)}.disabled(!model.awaitingFileApproval)
                Button("파일 전송 취소 (연결 종료)") {model.stop("파일 전송 취소됨")}.disabled(!model.fileBusy)
                Button("검증 저장 파일 목록 (연결 종료 후)") {model.refreshFiles()}.disabled(model.busy)
                ForEach(model.savedFiles) {file in
                    Button("검증 파일 저장: \(file.name) · \(file.size) bytes") {
                        guard let data=model.prepareExport(file) else {return}
                        exportDocument=ExportDocument(data:data);exportName=file.name
                        exportType=UTType(filenameExtension:(file.name as NSString).pathExtension) ?? .data
                        exporting=true
                    }.disabled(model.busy)
                }
                Text("수신은 앱 내부 임시 위치 → 크기/SHA-256 검증 → 충돌 없는 저장 순서입니다. 내보내기는 별도 사용자 선택입니다.").font(.caption)
                Text("IP/포트 수동 입력 · 백그라운드 수신 없음 · 세션 최대 10분").font(.caption)
            }.padding(20)
        }
        #if os(iOS)
        .fileImporter(isPresented:$importing,allowedContentTypes:[.item],allowsMultipleSelection:false) {result in
            if case .success(let urls)=result,let url=urls.first {model.stageFile(url)}
        }
        #endif
        .fileExporter(isPresented:$exporting,document:exportDocument,contentType:exportType,defaultFilename:exportName) {result in
            if case .success=result {model.exportCompleted(true)} else {model.exportCompleted(false)}
            exportDocument=nil
        }
        .onAppear {if manageLifecycle {model.setActive(phase == .active);if phase == .active {model.refreshFiles()}}}
        #if os(iOS)
        .onReceive(NotificationCenter.default.publisher(for:UIApplication.willResignActiveNotification)) {_ in if manageLifecycle {model.setActive(false)}}
        .onReceive(NotificationCenter.default.publisher(for:UIApplication.didEnterBackgroundNotification)) {_ in if manageLifecycle {model.setActive(false)}}
        .onReceive(NotificationCenter.default.publisher(for:UIApplication.willTerminateNotification)) {_ in if manageLifecycle {model.setActive(false)}}
        .onReceive(NotificationCenter.default.publisher(for:UIApplication.didBecomeActiveNotification)) {_ in if manageLifecycle {model.setActive(true);model.refreshFiles()}}
        #endif
        .onChange(of:phase) {_,next in if manageLifecycle {model.setActive(next == .active);if next == .active {model.refreshFiles()}}}
        .onDisappear {if manageLifecycle {model.setActive(false)}}
    }
    private func selectFile() {
        #if os(macOS)
        let panel=NSOpenPanel()
        panel.canChooseFiles=true;panel.canChooseDirectories=false;panel.allowsMultipleSelection=false
        panel.resolvesAliases=false
        if panel.runModal() == .OK,let url=panel.url {model.stageFile(url)}
        #else
        importing=true
        #endif
    }
    private func input(_ title:String,text:Binding<String>) -> some View {
        VStack(alignment:.leading,spacing:4) {
            Text(title).font(.caption)
            #if os(iOS)
            TextField(title,text:text).textFieldStyle(.roundedBorder)
                .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.asciiCapable)
            #else
            TextField(title,text:text).textFieldStyle(.roundedBorder).autocorrectionDisabled()
            #endif
        }
    }
}
