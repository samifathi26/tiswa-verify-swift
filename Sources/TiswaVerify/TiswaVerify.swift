#if canImport(UIKit) && canImport(AuthenticationServices)
import AuthenticationServices
import UIKit

/// Verify with Tiswa from an iPhone app, RFC 8252 style.
///
/// 1. Starts the check with your publishable key, your app redirect and a PKCE challenge.
/// 2. Opens the Tiswa app (universal link) when it is installed; otherwise the web sheet in an
///    `ASWebAuthenticationSession`.
/// 3. Tiswa sends the shopper back to your redirect with `?code=vc_…&state=…`. Pass every URL your
///    app opens to `TiswaVerify.handle(_:)`; the session's own callback and a poll of the check
///    are the backstops.
///
/// Send the result's `code`, `codeVerifier` and `redirectURI` to your backend, which calls
/// `POST /v1/oauth/token` with the secret key. If this throws, carry on at full price.
@MainActor
public final class TiswaVerify: NSObject {
    public let client: TiswaVerifyClient
    /// Checks waiting for the shopper to come back.
    private static var runs: [Run] = []

    public init(configuration: TiswaVerifyConfiguration) {
        client = TiswaVerifyClient(configuration: configuration)
    }

    /// Runs one check. Cancel the calling task to give up (the shopper keeps the full price).
    /// - Parameters:
    ///   - nonce: your cart or order id; it comes back to your server as `verification.nonce`.
    ///   - anchor: the window the web sheet is shown over (default: the key window).
    public func verify(nonce: String? = nil, anchor: ASPresentationAnchor? = nil) async throws -> TiswaVerifyResult {
        let check = try await client.start(nonce: nonce)
        let run = Run(check: check, anchor: anchor)
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                guard !run.isFinished else { return continuation.resume(throwing: TiswaVerifyError.cancelled) }
                run.continuation = continuation
                Self.runs.append(run)
                Task { await self.begin(run) }
            }
        } onCancel: {
            Task { @MainActor in run.finish(.failure(.cancelled)) }
        }
    }

    /// Call from `onOpenURL`, `scene(_:openURLContexts:)` or `scene(_:continue:)` (universal
    /// links). True when the URL was Tiswa's return for a running check.
    @discardableResult
    public static func handle(_ url: URL) -> Bool {
        for run in runs {
            guard let parsed = TiswaVerifyReturn.parse(url, check: run.check) else { continue }
            if case .failure(.stateMismatch) = parsed { continue }
            run.finish(parsed)
            return true
        }
        return false
    }

    // MARK: Running a check

    private func begin(_ run: Run) async {
        run.poll = Task { [client] in
            var returningSince: Date?
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64(client.configuration.pollInterval * 1_000_000_000))
                guard !Task.isCancelled else { return }
                switch try? await client.poll(run.check) {
                case .code(let code)?: run.finish(.success(run.check.result(code: code)))
                case .failed(let error)?: run.finish(.failure(error))
                case .returning?:
                    // Approved in Tiswa, which opened the return URL. Give it time to arrive.
                    let since = returningSince ?? Date()
                    returningSince = since
                    if Date().timeIntervalSince(since) > 30 { run.finish(.failure(.returnNotReceived)) }
                case .waiting?, nil: break
                }
            }
        }
        let openedTiswa = await UIApplication.shared.open(run.check.appLink, options: [.universalLinksOnly: true])
        if !openedTiswa, !run.isFinished { present(run) }
    }

    private func present(_ run: Run) {
        let redirect = run.check.redirectURI
        let url = run.check.sheetURL(base: client.configuration.sheetBase)
        let done: ASWebAuthenticationSession.CompletionHandler = { callbackURL, error in
            Task { @MainActor in
                if let callbackURL, let parsed = TiswaVerifyReturn.parse(callbackURL, check: run.check) {
                    run.finish(parsed)
                } else if (error as? ASWebAuthenticationSessionError)?.code == .canceledLogin {
                    // Closed by the shopper, or by us once the Tiswa app's return arrived.
                    run.finish(.failure(.cancelled))
                }
            }
        }
        let session: ASWebAuthenticationSession
        if #available(iOS 17.4, *) {
            let callback: ASWebAuthenticationSession.Callback = redirect.scheme == "https"
                ? .https(host: redirect.host ?? "", path: redirect.path)
                : .customScheme(redirect.scheme ?? "")
            session = ASWebAuthenticationSession(url: url, callback: callback, completionHandler: done)
        } else {
            // Before iOS 17.4 a universal-link redirect is not caught here: use a custom scheme
            // there, or rely on the Tiswa app's return and the poll.
            session = ASWebAuthenticationSession(url: url, callbackURLScheme: redirect.scheme == "https" ? nil : redirect.scheme,
                                                 completionHandler: done)
        }
        let window = run.anchor ?? UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
            .flatMap(\.windows).first(where: \.isKeyWindow) ?? ASPresentationAnchor()
        run.anchorProvider = AnchorProvider(window: window)
        session.presentationContextProvider = run.anchorProvider
        session.prefersEphemeralWebBrowserSession = false
        run.session = session
        session.start()
    }

    // MARK: One check

    @MainActor
    final class Run {
        let check: TiswaVerifyCheck
        let anchor: ASPresentationAnchor?
        var continuation: CheckedContinuation<TiswaVerifyResult, Error>?
        var session: ASWebAuthenticationSession?
        var poll: Task<Void, Never>?
        var anchorProvider: AnchorProvider?
        private(set) var isFinished = false

        init(check: TiswaVerifyCheck, anchor: ASPresentationAnchor?) {
            self.check = check
            self.anchor = anchor
        }

        /// The first answer wins; the rest are ignored.
        func finish(_ result: Result<TiswaVerifyResult, TiswaVerifyError>) {
            guard !isFinished else { return }
            isFinished = true
            poll?.cancel()
            session?.cancel()
            TiswaVerify.runs.removeAll { $0 === self }
            continuation?.resume(with: result.mapError { $0 as Error })
            continuation = nil
        }
    }

    final class AnchorProvider: NSObject, ASWebAuthenticationPresentationContextProviding {
        let window: ASPresentationAnchor
        init(window: ASPresentationAnchor) { self.window = window }
        func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor { window }
    }
}
#endif
