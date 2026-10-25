// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "TiswaVerify",
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [
        .library(name: "TiswaVerify", targets: ["TiswaVerify"]),
    ],
    targets: [
        .target(name: "TiswaVerify"),
        .testTarget(name: "TiswaVerifyTests", dependencies: ["TiswaVerify"]),
    ]
)
