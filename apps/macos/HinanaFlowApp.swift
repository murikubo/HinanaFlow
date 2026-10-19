import SwiftUI
import FlowDiagnostics
import FlowCore

@main struct HinanaFlowApp:App {
    #if HF_ANDROID_VALIDATION
    @StateObject private var diagnostic=AppleDiagnosticModel(profile:.androidInterop)
    #elseif HF_RC_VALIDATION
    @StateObject private var diagnostic=AppleDiagnosticModel(profile:.releaseCandidate)
    #else
    @StateObject private var diagnostic=AppleDiagnosticModel()
    #endif
    var body:some Scene {
        WindowGroup {AppleSharingView(model:diagnostic)}
    }
}
