import Foundation
import Combine
import Network
import FlowCore

public struct DiscoveredPeer:Identifiable,Sendable {
    public let id:UUID
    public let label:String
    let name:String
    let type:String
    let domain:String
    let interface:NWInterface
}
@MainActor public final class BonjourDiscovery:ObservableObject {
    @Published public private(set) var peers:[DiscoveredPeer]=[]
    @Published public private(set) var status="탐색 중지됨"
    @Published public private(set) var browsing=false
    @Published public private(set) var authenticatedID:UUID?
    var onInvalidated:(()->Void)?
    private var catalogue=BonjourCatalog()
    private var browser:NWBrowser?
    private var timer:Task<Void,Never>?
    private var generation=UUID()
    private let resolver=LocalServiceResolver()
    private var selected:UUID?
    public init() {}
    func start() {
        stop();browsing=true;status="60초 탐색 중 — 모든 발견 결과는 미인증"
        let token=generation
        let parameters=NWParameters.tcp
        parameters.includePeerToPeer=false;parameters.prohibitedInterfaceTypes=[.cellular,.loopback,.other]
        #if os(iOS)
        parameters.requiredInterfaceType = .wifi
        #endif
        let next=NWBrowser(for:.bonjour(type:BonjourLAN.serviceType,domain:"local."),using:parameters)
        browser=next
        next.browseResultsChangedHandler = {[weak self] results,_ in
            Task {@MainActor in
                guard let self,self.generation==token,self.browsing else {return}
                var advertisements:[BonjourCatalog.Advertisement]=[]
                var interfaces:[UInt32:NWInterface]=[:]
                for result in results.prefix(64) {
                    guard case .service(let name,let type,let domain,_) = result.endpoint,
                          BonjourLAN.validService(name:name,type:type,domain:domain) else {continue}
                    for interface in result.interfaces.prefix(4) where [.wifi,.wiredEthernet].contains(interface.type) {
                        #if os(iOS)
                        guard interface.type == .wifi,interface.name=="en0" else {continue}
                        #endif
                        interfaces[UInt32(interface.index)]=interface
                        advertisements.append(.init(name:name,type:type,domain:domain,interfaceIndex:UInt32(interface.index)))
                    }
                }
                self.catalogue.replace(advertisements)
                self.peers=self.catalogue.entries.compactMap {entry in
                    let a=entry.advertisement
                    guard let interface=interfaces[a.interfaceIndex] else {return nil}
                    return DiscoveredPeer(id:entry.id,label:BonjourLAN.label(a.name),name:a.name,type:a.type,domain:a.domain,interface:interface)
                }.sorted {$0.id.uuidString<$1.id.uuidString}
                if let selected=self.selected,!self.peers.contains(where:{$0.id==selected}) {self.resolver.cancel();self.onInvalidated?()}
            }
        }
        next.stateUpdateHandler = {[weak self] state in
            if case .failed=state {Task {@MainActor in
                guard let self,self.generation==token,self.browsing else {return}
                self.stop();self.status="탐색 실패 — 권한/네트워크 확인 또는 수동 입력 사용";self.onInvalidated?()
            }}
        }
        next.start(queue:.main)
        timer=Task {[weak self] in
            try? await Task.sleep(for:.seconds(60))
            guard !Task.isCancelled,let self,self.generation==token else {return}
            self.stop();self.status="탐색 시간 만료 — 다시 탐색하세요";self.onInvalidated?()
        }
    }
    func resolve(_ id:UUID,completion:@escaping (NWEndpoint?,NWInterface?)->Void) {
        guard browsing,let peer=peers.first(where:{$0.id==id}) else {completion(nil,nil);return}
        selected=id;let token=generation;status="선택한 로컬 서비스 해석 중 — 미인증"
        resolver.start(name:peer.name,type:peer.type,domain:peer.domain,interface:peer.interface) {[weak self] endpoint in
            guard let self,self.generation==token,self.selected==id,self.peers.contains(where:{$0.id==id}) else {return}
            completion(endpoint,peer.interface)
        }
    }
    /// A remembered selection is untrusted metadata only. Explicit send/connect resolves it afresh.
    func resolveRemembered(_ peer:DiscoveredPeer,completion:@escaping (NWEndpoint?,NWInterface?)->Void) {
        stop();selected=peer.id;peers=[peer];let token=generation
        status="선택 기기 주소 재확인 중 — 미인증"
        resolver.start(name:peer.name,type:peer.type,domain:peer.domain,interface:peer.interface) {[weak self] endpoint in
            guard let self,self.generation==token,self.selected==peer.id else {return}
            completion(endpoint,peer.interface)
        }
    }
    func authenticated() {
        authenticatedID=selected;browser?.cancel();browser=nil;timer?.cancel();timer=nil
        resolver.cancel();browsing=false
        status="현재 TLS 상대 키 검증 완료 — 이름/주소는 신뢰 근거가 아닙니다"
    }
    func stop() {
        generation=UUID();resolver.cancel();browser?.cancel();browser=nil;timer?.cancel();timer=nil
        catalogue.clear();peers=[];selected=nil;authenticatedID=nil;browsing=false;status="탐색 중지됨"
    }
}
