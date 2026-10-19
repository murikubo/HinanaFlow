import SwiftUI
import UniformTypeIdentifiers
import FlowCore
#if os(iOS)
import UIKit
#else
import AppKit
#endif

@MainActor public struct AppleSharingView:View {
    @ObservedObject private var model:AppleDiagnosticModel
    @ObservedObject private var discovery:BonjourDiscovery
    @Environment(\.scenePhase) private var phase
    @State private var selected:DiscoveredPeer?
    @State private var showDiagnostics=false
    @State private var showPairing=false
    @State private var pendingAction:Action?
    @State private var importing=false
    @State private var exporting=false
    @State private var exportDocument:ExportDocument?
    @State private var exportName="received.bin"
    @State private var exportType=UTType.data
    @State private var showReceived=false
    private enum Action {case receive,connect,send}
    public init(model:AppleDiagnosticModel) {self.model=model;self.discovery=model.discovery}
    public var body:some View {
        NavigationStack {
            ScrollView {
                VStack(alignment:.leading,spacing:20) {
                    header
                    if model.profile == .androidInterop {Text("Android 연동 검증 전용 · 기존 키/신뢰/파일과 분리됨").font(.headline).foregroundStyle(.orange)}
                    if model.profile == .releaseCandidate {Text("RC 검증 전용 · 운영 키/신뢰/파일과 분리됨").font(.headline).foregroundStyle(.orange)}
                    statusCard
                    consentCards
                    if showReceived {receivedCard} else {sendCard;receiveCard;textCard}
                    if !model.fileSummary.isEmpty {Text(model.fileSummary).font(.callout).accessibilityIdentifier("fileStatus")}
                    if !model.userNotice.isEmpty {Text(model.userNotice).font(.footnote).foregroundStyle(.secondary)}
                    Text("같은 네트워크에서, 앱을 열어 둔 동안만 공유합니다.").font(.footnote).foregroundStyle(.secondary)
                }.padding(20).frame(maxWidth:760)
            }.frame(maxWidth:.infinity).background(Color.primary.opacity(0.035))
            .navigationTitle("Hinana Flow")
            .toolbar {
                ToolbarItem {Button {showReceived.toggle();if showReceived {model.refreshFiles()}} label:{Label(showReceived ? "공유":"받은 파일",systemImage:showReceived ? "arrow.up.arrow.down":"tray")}}
                ToolbarItem {Button {showDiagnostics=true} label:{Label("진단",systemImage:"gearshape")}.accessibilityIdentifier("openDiagnostics")}
            }
        }
        .sheet(isPresented:$showDiagnostics) {
            NavigationStack {
                AppleDiagnosticView(model:model,manageLifecycle:false)
                    .navigationTitle("연결 진단")
                    .toolbar {ToolbarItem {Button("닫기") {showDiagnostics=false}}}
            }.frame(minWidth:320,minHeight:540)
        }
        .sheet(isPresented:$showPairing,onDismiss:{pendingAction=nil}) {pairingSheet}
        #if os(iOS)
        .fileImporter(isPresented:$importing,allowedContentTypes:[.item],allowsMultipleSelection:false) {result in
            if case .success(let urls)=result,let url=urls.first {model.stageFile(url)}
        }
        #endif
        .fileExporter(isPresented:$exporting,document:exportDocument,contentType:exportType,defaultFilename:exportName) {result in
            if case .success=result {model.exportCompleted(true)} else {model.exportCompleted(false)}
            exportDocument=nil
        }
        .onAppear {model.setActive(phase == .active);if phase == .active {model.refreshFiles()}}
        .onChange(of:phase) {_,next in model.setActive(next == .active);if next == .active {model.refreshFiles()}}
        #if os(iOS)
        .onReceive(NotificationCenter.default.publisher(for:UIApplication.willResignActiveNotification)) {_ in model.setActive(false)}
        .onReceive(NotificationCenter.default.publisher(for:UIApplication.didEnterBackgroundNotification)) {_ in model.setActive(false)}
        .onReceive(NotificationCenter.default.publisher(for:UIApplication.willTerminateNotification)) {_ in model.setActive(false)}
        .onReceive(NotificationCenter.default.publisher(for:UIApplication.didBecomeActiveNotification)) {_ in model.setActive(true);model.refreshFiles()}
        #endif
        .onDisappear {model.setActive(false)}
    }
    private var header:some View {
        HStack(spacing:12) {
            Image(systemName:"arrow.up.arrow.down.circle.fill").font(.largeTitle).foregroundStyle(.blue)
            VStack(alignment:.leading,spacing:4) {
                Text("Hinana Flow").font(.title.bold())
                Text("가까운 기기로 안전하게 공유").font(.subheadline).foregroundStyle(.secondary)
            }
        }
    }
    private var statusCard:some View {
        card {
            Label(model.connected ? "기기 확인 완료":model.isAdvertising ? "받기 대기 중":model.busy ? "상대 기기 확인 중":discovery.browsing ? "주변 기기 찾는 중":"공유할 준비가 됐어요",systemImage:model.connected ? "checkmark.shield.fill":"wifi")
                .font(.headline).accessibilityIdentifier("sharingStatus")
            if model.connected {Text("연결된 상대를 확인했습니다. 수신은 매번 승인합니다.").font(.subheadline)}
            if model.busy || discovery.browsing {Button("연결·대기 종료",role:.destructive) {model.stop()}}
        }
    }
    private var sendCard:some View {
        card {
            Label("보내기",systemImage:"paperplane").font(.title3.bold())
            Button("주변 기기 찾기") {
                guard prepareIdentity() else {return};selected=nil;model.browseBonjour()
            }.buttonStyle(.bordered).disabled(model.busy || phase != .active)
            if discovery.browsing && discovery.peers.isEmpty {Text("상대 기기에서 ‘받기 대기’를 눌러주세요.").font(.subheadline).foregroundStyle(.secondary)}
            ForEach(discovery.peers) {peer in
                Button {selected=peer;model.userNotice="기기를 선택했습니다. 보낼 파일을 골라주세요"} label:{
                    HStack {
                        Image(systemName:selected?.id==peer.id ? "checkmark.circle.fill":"rectangle.on.rectangle")
                        VStack(alignment:.leading) {
                            Text(peer.label).lineLimit(2)
                            Text("발견된 이름 · 연결 전 미확인").font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                    }.padding(.vertical,6)
                }.buttonStyle(.plain).disabled(model.busy).accessibilityIdentifier("selectNearbyPeer")
            }
            if let selected {
                Text("선택: \(selected.label)").font(.subheadline)
                Text(model.connected ? "현재 연결에서 상대 키를 확인했습니다":"보낼 때 상대를 다시 확인합니다. 이름만으로 신뢰하지 않습니다.").font(.caption).foregroundStyle(.secondary)
                Button("파일 선택") {selectFile()}.buttonStyle(.bordered).disabled(model.fileBusy)
                Button("파일 보내기") {request(.send)}.buttonStyle(.borderedProminent)
                    .disabled(!model.preparedFile || model.busy || phase != .active)
                if !model.preparedFile && !model.busy {Button("기기에 연결") {request(.connect)}.buttonStyle(.bordered)}
            } else if !discovery.browsing {Text("기기를 찾고 선택한 다음 파일을 골라 보내세요.").foregroundStyle(.secondary)}
        }
    }
    private var receiveCard:some View {
        card {
            Label("받기",systemImage:"square.and.arrow.down").font(.title3.bold())
            Text("상대가 이 기기를 찾을 수 있도록 60초 동안 대기합니다.").font(.subheadline)
            Button(model.connected && model.isAdvertising ? "연결 종료":model.isAdvertising ? "받기 대기 중지":"받기 대기") {
                if model.isAdvertising {model.stop()} else {request(.receive)}
            }.buttonStyle(.borderedProminent).disabled((model.busy && !model.isAdvertising) || phase != .active)
            Text("화면을 잠그거나 다른 앱으로 이동하면 대기가 끝납니다.").font(.caption).foregroundStyle(.secondary)
        }
    }
    @ViewBuilder private var consentCards:some View {
        if model.awaitingFileApproval {
            card {
                Label("파일이 도착했어요",systemImage:"doc.badge.arrow.up").font(.headline)
                Text(model.fileConsent)
                HStack {Button("파일 받기") {model.decideFile(true)}.buttonStyle(.borderedProminent);Button("거절",role:.destructive) {model.decideFile(false)}}
            }
        }
        if model.awaitingApproval {
            card {
                Label("텍스트 수신 요청",systemImage:"text.bubble").font(.headline)
                Text(model.pendingSummary)
                HStack {Button("텍스트 받기") {model.decide(true)}.buttonStyle(.borderedProminent);Button("거절",role:.destructive) {model.decide(false)}}
            }
        }
        if model.fileBusy {Button("파일 전송 취소",role:.destructive) {model.stop("사용자가 파일 전송 취소")}}
    }
    private var textCard:some View {
        card {
            if model.connected {
                DisclosureGroup("텍스트 보내기") {
                    TextEditor(text:$model.draft).frame(height:90).border(.secondary.opacity(0.25))
                    Button("텍스트 보내기") {model.send()}.disabled(!model.canSend || model.draft.isEmpty)
                }
            }
            if !model.receivedText.isEmpty {
                Text("받은 텍스트").font(.headline)
                Text(model.receivedText).textSelection(.enabled).accessibilityIdentifier("receivedText")
            }
            if !model.connected && model.receivedText.isEmpty {Text("텍스트도 연결 후 상대의 승인을 받아 보낼 수 있습니다.").font(.caption).foregroundStyle(.secondary)}
        }
    }
    private var receivedCard:some View {
        card {
            Label("받은 파일",systemImage:"tray.full").font(.title3.bold())
            Button("목록 새로 고침") {model.refreshFiles()}
            if model.savedFiles.isEmpty {Text("받은 파일이 아직 없습니다.").foregroundStyle(.secondary)}
            ForEach(model.savedFiles) {file in
                VStack(alignment:.leading,spacing:8) {
                    Text(file.name).font(.headline)
                    Text(ByteCountFormatter.string(fromByteCount:Int64(file.size),countStyle:.file)).font(.caption).foregroundStyle(.secondary)
                    Button("저장 위치 선택") {export(file)}.buttonStyle(.bordered)
                }.padding(.vertical,8)
            }
            Text("파일을 자동으로 열지 않습니다. 저장 창을 열면 현재 연결이 종료됩니다.").font(.caption).foregroundStyle(.secondary)
        }
    }
    private var pairingSheet:some View {
        NavigationStack {
            ScrollView {
                VStack(alignment:.leading,spacing:18) {
                    Text("처음 연결하는 기기 확인").font(.title2.bold())
                    Text("두 기기 화면의 전체 지문을 서로 대조하세요. 발견된 이름이나 주소로 대신 확인할 수 없습니다.")
                    Text("이 기기의 지문").font(.headline)
                    Text(model.fingerprint).font(.system(.caption,design:.monospaced)).textSelection(.enabled)
                    Text("상대 화면에서 직접 확인한 지문").font(.headline)
                    TextField("64자리 공개키 지문",text:$model.expectedFingerprint).textFieldStyle(.roundedBorder).autocorrectionDisabled()
                        .onChange(of:model.expectedFingerprint) {_,_ in model.confirmedOOB=false}
                    Toggle("상대 화면의 전체 지문과 일치함을 직접 확인했습니다",isOn:$model.confirmedOOB)
                    Button("확인하고 계속") {
                        let action=pendingAction;pendingAction=nil;showPairing=false
                        if let action {perform(action)}
                    }.buttonStyle(.borderedProminent).disabled(!model.pairingConfigured)
                    Text("신뢰 정보는 실제 연결에서 양쪽 인증이 끝난 뒤에만 저장됩니다.").font(.caption).foregroundStyle(.secondary)
                }.padding(20)
            }.navigationTitle("기기 확인").toolbar {ToolbarItem {Button("취소") {pendingAction=nil;showPairing=false}}}
        }.frame(minWidth:320,minHeight:520)
    }
    private func prepareIdentity()->Bool {
        if model.fingerprint.isEmpty {model.prepare()}
        return !model.fingerprint.isEmpty
    }
    private func request(_ action:Action) {
        guard prepareIdentity() else {return}
        if !model.pairingConfigured {pendingAction=action;showPairing=true} else {perform(action)}
    }
    private func perform(_ action:Action) {
        switch action {
        case .receive:model.advertiseBonjour()
        case .connect:if let selected {model.connectChosen(selected,sendPreparedFile:false)}
        case .send:if let selected {model.connectChosen(selected,sendPreparedFile:true)}
        }
    }
    private func selectFile() {
        model.stop("파일 선택을 위한 연결 종료")
        #if os(macOS)
        let panel=NSOpenPanel();panel.canChooseFiles=true;panel.canChooseDirectories=false;panel.allowsMultipleSelection=false;panel.resolvesAliases=false
        if panel.runModal() == .OK,let url=panel.url {model.stageFile(url)}
        #else
        importing=true
        #endif
    }
    private func export(_ file:ReceivedFile) {
        if model.busy || discovery.browsing {model.stop("파일 저장을 위한 연결 종료")}
        guard let data=model.prepareExport(file) else {return}
        model.refreshFiles();exportDocument=ExportDocument(data:data);exportName=file.name
        exportType=UTType(filenameExtension:(file.name as NSString).pathExtension) ?? .data;exporting=true
    }
    private func card<Content:View>(@ViewBuilder _ content:()->Content)->some View {
        VStack(alignment:.leading,spacing:14,content:content).frame(maxWidth:.infinity,alignment:.leading)
            .padding(18).background(.background,in:RoundedRectangle(cornerRadius:18)).overlay(RoundedRectangle(cornerRadius:18).stroke(.primary.opacity(0.06)))
    }
}
