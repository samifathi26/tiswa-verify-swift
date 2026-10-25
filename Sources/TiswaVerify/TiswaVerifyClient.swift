import Foundation

/// Your app's Verify with Tiswa setup. Use the publishable key (`tsw_pk_…`), never the secret one.
public struct TiswaVerifyConfiguration: Sendable {
    public var publishableKey: String
    public var program: String
    /// Registered in the console for this client: a universal link you own
    /// (`https://shop.example.sa/tiswa/app-callback`) or a custom scheme (`shopexample://tiswa`).
    public var redirectURI: URL
    public var apiBase: URL
    public var sheetBase: URL
    /// How often the check is polled while the shopper is away (the backstop for a lost return).
    public var pollInterval: TimeInterval

    public init(publishableKey: String, program: String, redirectURI: URL,
                apiBase: URL = URL(string: "https://api.tiswa.app/v1")!,
                sheetBase: URL = URL(string: "https://verify.tiswa.app")!,
                pollInterval: TimeInterval = 2) {
        self.publishableKey = publishableKey
        self.program = program
        self.redirectURI = redirectURI
        self.apiBase = apiBase
        self.sheetBase = sheetBase
        self.pollInterval = pollInterval
    }
}

/// What your backend needs for `POST /v1/oauth/token`: the code, the verifier and the redirect.
public struct TiswaVerifyResult: Equatable, Sendable {
    public let code: String
    public let codeVerifier: String
    public let redirectURI: String
    public let state: String
    public let requestID: String
}

public enum TiswaVerifyError: Error, Equatable, Sendable {
    /// The shopper closed the sheet or said not now. Carry on at full price.
    case cancelled
    /// Not a verified student for this offer (the reason stays with the shopper).
    case notEligible
    /// The check's 10 minutes ran out.
    case expired
    /// A return URL whose state is not this check's. Ignore it.
    case stateMismatch
    /// Tiswa approved and sent the shopper back, but the return URL never reached the app
    /// (`handle(_:)` not wired up?). The code is spent; start a new check.
    case returnNotReceived
    /// Tiswa answered with an error: `code` is the API's error code (`invalid_redirect_uri`, …).
    case api(status: Int, code: String, message: String)
    case invalidResponse
}

/// A started check.
public struct TiswaVerifyCheck: Equatable, Sendable {
    public let requestID: String
    /// `https://tiswa.app/v/#r=<id>`: opens the Tiswa app when it is installed.
    public let appLink: URL
    public let pkce: TiswaPKCE
    public let state: String
    public let browserSecret: String
    public let nonce: String?
    public let redirectURI: URL

    /// The web sheet, for phones without Tiswa.
    public func sheetURL(base: URL) -> URL { base.appendingPathComponent("r").appendingPathComponent(requestID) }

    func result(code: String) -> TiswaVerifyResult {
        TiswaVerifyResult(code: code, codeVerifier: pkce.verifier, redirectURI: redirectURI.absoluteString, state: state, requestID: requestID)
    }
}

/// What a poll said.
public enum TiswaVerifyPoll: Equatable, Sendable {
    case waiting
    case code(String)
    /// Approved, and the code already went out through the return URL.
    case returning
    case failed(TiswaVerifyError)
}

/// The network half: start the check and poll it. No UI; used by `TiswaVerify` and testable alone.
public struct TiswaVerifyClient: Sendable {
    public let configuration: TiswaVerifyConfiguration
    let send: @Sendable (URLRequest) async throws -> (Data, HTTPURLResponse)

    public init(configuration: TiswaVerifyConfiguration, session: URLSession = .shared) {
        self.init(configuration: configuration) { request in
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse else { throw TiswaVerifyError.invalidResponse }
            return (data, http)
        }
    }

    init(configuration: TiswaVerifyConfiguration, send: @escaping @Sendable (URLRequest) async throws -> (Data, HTTPURLResponse)) {
        self.configuration = configuration
        self.send = send
    }

    /// `POST /authorize/start` with surface `app_link`, the app redirect and a PKCE challenge.
    /// `nonce` is your cart or order id; it comes back to your server with the verification.
    public func start(nonce: String? = nil) async throws -> TiswaVerifyCheck {
        let pkce = TiswaPKCE.generate()
        let state = TiswaPKCE.randomToken(bytes: 16)
        let secret = TiswaPKCE.randomToken(bytes: 32)
        var body: [String: String] = [
            "program": configuration.program, "surface": "app_link", "redirect_uri": configuration.redirectURI.absoluteString,
            "code_challenge": pkce.challenge, "code_challenge_method": "S256", "state": state, "browser_secret": secret,
        ]
        if let nonce { body["nonce"] = nonce }
        let reply = try await post("authorize/start", body)
        guard let id = reply["request_id"] as? String, let link = (reply["app_link"] as? String).flatMap(URL.init(string:)) else {
            throw TiswaVerifyError.invalidResponse
        }
        return TiswaVerifyCheck(requestID: id, appLink: link, pkce: pkce, state: state, browserSecret: secret, nonce: nonce,
                                redirectURI: configuration.redirectURI)
    }

    /// `POST /authorize/{id}/result`.
    public func poll(_ check: TiswaVerifyCheck) async throws -> TiswaVerifyPoll {
        let reply = try await post("authorize/\(check.requestID)/result", ["browser_secret": check.browserSecret])
        switch reply["status"] as? String {
        case "open": return .waiting
        case "approved":
            if let code = reply["code"] as? String, code.hasPrefix("vc_") { return .code(code) }
            return .returning
        case "declined": return .failed(.notEligible)
        case "expired": return .failed(.expired)
        default: throw TiswaVerifyError.invalidResponse
        }
    }

    private func post(_ path: String, _ body: [String: String]) async throws -> [String: Any] {
        var request = URLRequest(url: configuration.apiBase.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(configuration.publishableKey, forHTTPHeaderField: "Tiswa-Publishable-Key")
        request.httpBody = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
        request.timeoutInterval = 10
        let (data, response) = try await send(request)
        let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
        guard (200..<300).contains(response.statusCode) else {
            let error = json["error"] as? [String: Any]
            throw TiswaVerifyError.api(status: response.statusCode, code: error?["code"] as? String ?? "http_\(response.statusCode)",
                                       message: error?["message"] as? String ?? "")
        }
        return json
    }
}

/// Reads the URL Tiswa sends the shopper back with: `<redirect>?code=vc_…&state=…`
/// (or `?error=access_denied&state=…` from the web sheet).
public enum TiswaVerifyReturn {
    /// Nil when the URL is not for this redirect at all (leave it to the rest of your app).
    public static func parse(_ url: URL, check: TiswaVerifyCheck) -> Result<TiswaVerifyResult, TiswaVerifyError>? {
        guard matches(url, redirect: check.redirectURI),
              let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems else { return nil }
        let value = { (name: String) in items.first { $0.name == name }?.value }
        guard value("state") == check.state else { return .failure(.stateMismatch) }
        if let error = value("error") { return .failure(error == "access_denied" ? .cancelled : .api(status: 0, code: error, message: "")) }
        guard let code = value("code"), code.hasPrefix("vc_") else { return .failure(.invalidResponse) }
        return .success(check.result(code: code))
    }

    /// Same scheme, host and path as the registered redirect; its own query is allowed.
    public static func matches(_ url: URL, redirect: URL) -> Bool {
        guard let a = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let b = URLComponents(url: redirect, resolvingAgainstBaseURL: false) else { return false }
        return a.scheme?.lowercased() == b.scheme?.lowercased() && a.host?.lowercased() == b.host?.lowercased()
            && a.path == b.path && a.port == b.port
    }
}
