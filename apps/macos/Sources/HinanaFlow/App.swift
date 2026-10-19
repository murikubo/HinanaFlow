import SwiftUI
import FlowDiagnostics

@main struct HinanaFlowApp:App {
    @StateObject private var diagnostic=AppleDiagnosticModel()
    var body:some Scene {
        WindowGroup {
            AppleSharingView(model:diagnostic).frame(minWidth:650,minHeight:760)
        }
    }
}
