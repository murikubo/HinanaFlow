// Preserved for a future Bonjour task; the current manual-IP diagnostic never instantiates this model.
import SwiftUI
import Network
import FlowCore
import FlowDiagnostics

@MainActor final class DiscoveryModel: ObservableObject {
    @Published var names: [String] = []
    @Published var status = "중지됨"
    private var browser: NWBrowser?
    private var expiry: Task<Void, Never>?
    private var generation = UUID()
    func start() {
        stop(); names = []; status = "탐색 중 — 발견된 기기는 인증되지 않았습니다"
        let token = UUID(); generation = token
        let parameters = NWParameters.tcp
        parameters.includePeerToPeer = false
        parameters.prohibitedInterfaceTypes = [.cellular]
        let next = NWBrowser(for: .bonjour(type: "_hinanaflow._tcp", domain: "local."), using: parameters)
        browser = next
        next.browseResultsChangedHandler = { [weak self] results, _ in
            let labels = results.prefix(128).map { result -> String in
                if case let .service(name, _, _, _) = result.endpoint {
                    return String(name.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) }.prefix(128))
                }
                return "기기"
            }.sorted()
            Task { @MainActor in
                guard let self, self.generation == token else { return }
                self.names = labels
            }
        }
        next.stateUpdateHandler = { [weak self] state in
            if case .failed = state {
                Task { @MainActor in
                    guard let self, self.generation == token else { return }
                    self.stop(); self.status = "탐색 실패 — 로컬 네트워크 권한을 확인하세요"
                }
            }
        }
        next.start(queue: .main)
        expiry = Task { [weak self] in
            try? await Task.sleep(for: .seconds(30))
            guard !Task.isCancelled, let self, self.generation == token else { return }
            self.stop()
        }
    }
    func stop() {
        generation = UUID(); expiry?.cancel(); expiry = nil
        browser?.cancel(); browser = nil; status = "중지됨"
    }
}


