// swift-tools-version: 6.0
import PackageDescription
// FlowDiagnostics contains the everyday sharing UI and the optional diagnostic screen.
let package = Package(name:"HinanaFlowApple", platforms:[.macOS(.v14),.iOS(.v18)], products:[
    .library(name:"FlowCore",targets:["FlowCore"]),
    .library(name:"FlowDiagnostics",targets:["FlowDiagnostics"])
], targets:[
    .target(name:"FlowCore"),
    .target(name:"FlowDiagnostics",dependencies:["FlowCore"]),
    .executableTarget(name:"FlowCoreVectorTests",dependencies:["FlowCore","FlowDiagnostics"],path:"Tests/FlowCoreVectorTests")
])
