/// Closed, build-selected namespaces. Never selected from network input.
/// RC builds use separate keys, trust and files; there is no production fallback.
public enum ValidationProfile: Sendable {
    case production, releaseCandidate
    public var identityLabel:String {
        #if os(macOS)
        let base="dev.hinana.flow.identity.secureenclave.v1"
        #else
        let base="dev.hinana.flow.identity.v1"
        #endif
        return self == .production ? base : base+".rc-alpha1"
    }
    public var trustService:String {self == .production ? "dev.hinana.flow.trust.v1" : "dev.hinana.flow.trust.v1.rc-alpha1"}
    public var transferDirectory:String {self == .production ? "HinanaFlowTransfers" : "HinanaFlowRCAlpha1Transfers"}
}
