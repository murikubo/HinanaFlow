// swift-tools-version: 6.0
import PackageDescription
let package = Package(name:"HinanaFlow",platforms:[.macOS(.v14)],products:[
    .executable(name:"HinanaFlow",targets:["HinanaFlow"])
], dependencies:[.package(path:"../../packages/HinanaFlowApple")],targets:[
    .executableTarget(name:"HinanaFlow",dependencies:[
        .product(name:"FlowCore",package:"HinanaFlowApple"),
        .product(name:"FlowDiagnostics",package:"HinanaFlowApple")
    ])
])
