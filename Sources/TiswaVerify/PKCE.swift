import CryptoKit
import Foundation
import Security

/// RFC 7636 proof key: the verifier stays in the app until your backend exchanges the code;
/// only its S256 challenge goes to Tiswa.
public struct TiswaPKCE: Equatable, Sendable {
    public let verifier: String
    public let challenge: String

    public init(verifier: String) {
        self.verifier = verifier
        challenge = TiswaPKCE.base64URL(Data(SHA256.hash(data: Data(verifier.utf8))))
    }

    /// A fresh 43-character verifier from 32 random bytes.
    public static func generate() -> TiswaPKCE { TiswaPKCE(verifier: randomToken(bytes: 32)) }

    static func randomToken(bytes count: Int) -> String {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed")
        return base64URL(Data(bytes))
    }

    static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
