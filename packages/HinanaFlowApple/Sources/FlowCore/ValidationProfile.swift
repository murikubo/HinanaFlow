/// Closed, build-selected namespaces. Never selected from network input.
/// RC builds use separate keys, trust and files; there is no production fallback.
public enum ValidationProfile: Sendable {
    case production, releaseCandidate, androidInterop
    public var identityLabel:String {
        #if os(macOS)
        let base="dev.hinana.flow.identity.secureenclave.v1"
        #else
        let base="dev.hinana.flow.identity.v1"
        #endif
        switch self {
        case .production:return base
        case .releaseCandidate:return base+".rc-alpha1"
        case .androidInterop:return base+".android-alpha1"
        }
    }
    public var trustService:String {
        switch self {
        case .production:return "dev.hinana.flow.trust.v1"
        case .releaseCandidate:return "dev.hinana.flow.trust.v1.rc-alpha1"
        case .androidInterop:return "dev.hinana.flow.trust.v1.android-alpha1"
        }
    }
    public var transferDirectory:String {
        switch self {
        case .production:return "HinanaFlowTransfers"
        case .releaseCandidate:return "HinanaFlowRCAlpha1Transfers"
        case .androidInterop:return "HinanaFlowAndroidAlpha1Transfers"
        }
    }
}
