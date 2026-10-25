import Foundation
import XCTest
@testable import TiswaVerify

final class TiswaVerifyTests: XCTestCase {
    private let config = TiswaVerifyConfiguration(publishableKey: "tsw_pk_test_x", program: "prg_1",
                                                  redirectURI: URL(string: "shopexample://tiswa/return")!,
                                                  apiBase: URL(string: "https://api.example.test/v1")!)

    func testPKCEMatchesRFC7636AppendixB() {
        let pkce = TiswaPKCE(verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        XCTAssertEqual(pkce.challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
        let fresh = TiswaPKCE.generate()
        XCTAssertEqual(fresh.verifier.count, 43)
        XCTAssertNotNil(fresh.challenge.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression))
        XCTAssertNotEqual(fresh.verifier, TiswaPKCE.generate().verifier)
    }

    func testStartSendsAnAppCheckWithPKCE() async throws {
        let sent = Box<URLRequest>()
        let client = TiswaVerifyClient(configuration: config) { request in
            sent.value = request
            return Self.reply(200, #"{"request_id":"9b1c","env":"test","app_link":"https://tiswa.app/v/#r=9b1c"}"#)
        }
        let check = try await client.start(nonce: "cart_1")
        let request = try XCTUnwrap(sent.value)
        XCTAssertEqual(request.url?.absoluteString, "https://api.example.test/v1/authorize/start")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Tiswa-Publishable-Key"), "tsw_pk_test_x")
        let body = try XCTUnwrap(JSONSerialization.jsonObject(with: try XCTUnwrap(request.httpBody)) as? [String: String])
        XCTAssertEqual(body["surface"], "app_link")
        XCTAssertEqual(body["redirect_uri"], "shopexample://tiswa/return")
        XCTAssertEqual(body["code_challenge"], check.pkce.challenge)
        XCTAssertEqual(body["code_challenge_method"], "S256")
        XCTAssertEqual(body["state"], check.state)
        XCTAssertEqual(body["nonce"], "cart_1")
        XCTAssertNil(body["code_verifier"], "the verifier never leaves the app")
        XCTAssertGreaterThanOrEqual(try XCTUnwrap(body["browser_secret"]).count, 32)
        XCTAssertEqual(check.appLink.absoluteString, "https://tiswa.app/v/#r=9b1c")
        XCTAssertEqual(check.sheetURL(base: config.sheetBase).absoluteString, "https://verify.tiswa.app/r/9b1c")
    }

    func testAPIErrorsCarryTheirCode() async {
        let client = TiswaVerifyClient(configuration: config) { _ in
            Self.reply(400, #"{"error":{"code":"invalid_redirect_uri","message":"Register it first."}}"#)
        }
        do {
            _ = try await client.start()
            XCTFail("should throw")
        } catch {
            XCTAssertEqual(error as? TiswaVerifyError, .api(status: 400, code: "invalid_redirect_uri", message: "Register it first."))
        }
    }

    func testPollStates() async throws {
        let answers = Box<[String]>([#"{"status":"open"}"#, #"{"status":"approved","code_already_issued":true,"state":"s"}"#,
                                     #"{"status":"approved","code":"vc_ab","state":"s"}"#, #"{"status":"declined"}"#,
                                     #"{"status":"expired"}"#])
        let client = TiswaVerifyClient(configuration: config) { request in
            XCTAssertTrue(request.url!.path.hasSuffix("/authorize/9b1c/result"))
            return Self.reply(200, answers.value!.removeFirst())
        }
        let check = Self.check()
        let polls = [try await client.poll(check), try await client.poll(check), try await client.poll(check),
                     try await client.poll(check), try await client.poll(check)]
        XCTAssertEqual(polls, [.waiting, .returning, .code("vc_ab"), .failed(.notEligible), .failed(.expired)])
    }

    func testReturnURLParsing() throws {
        let check = Self.check()
        let ok = TiswaVerifyReturn.parse(URL(string: "shopexample://tiswa/return?code=vc_0a1b&state=st%201%26x")!, check: check)
        XCTAssertEqual(try ok?.get(), TiswaVerifyResult(code: "vc_0a1b", codeVerifier: check.pkce.verifier,
                                                        redirectURI: "shopexample://tiswa/return", state: "st 1&x", requestID: "9b1c"))
        XCTAssertEqual(parseError("shopexample://tiswa/return?code=vc_1&state=other", check), .stateMismatch)
        XCTAssertEqual(parseError("shopexample://tiswa/return?error=access_denied&state=st%201%26x", check), .cancelled)
        XCTAssertEqual(parseError("shopexample://tiswa/return?code=nope&state=st%201%26x", check), .invalidResponse)
        XCTAssertNil(TiswaVerifyReturn.parse(URL(string: "shopexample://orders/12?code=vc_1")!, check: check), "another deep link is not ours")
        XCTAssertNil(TiswaVerifyReturn.parse(URL(string: "otherapp://tiswa/return?code=vc_1")!, check: check))

        let link = URL(string: "https://shop.example.sa/tiswa/app-callback?from=tiswa")!
        XCTAssertTrue(TiswaVerifyReturn.matches(URL(string: "https://SHOP.example.sa/tiswa/app-callback?from=tiswa&code=vc_1")!, redirect: link))
        XCTAssertFalse(TiswaVerifyReturn.matches(URL(string: "https://shop.example.sa/tiswa/other?code=vc_1")!, redirect: link))
    }

    // MARK: Helpers

    private func parseError(_ url: String, _ check: TiswaVerifyCheck) -> TiswaVerifyError? {
        guard case .failure(let error)? = TiswaVerifyReturn.parse(URL(string: url)!, check: check) else { return nil }
        return error
    }

    private static func check() -> TiswaVerifyCheck {
        TiswaVerifyCheck(requestID: "9b1c", appLink: URL(string: "https://tiswa.app/v/#r=9b1c")!, pkce: .generate(), state: "st 1&x",
                         browserSecret: String(repeating: "b", count: 43), nonce: nil, redirectURI: URL(string: "shopexample://tiswa/return")!)
    }

    private static func reply(_ status: Int, _ json: String) -> (Data, HTTPURLResponse) {
        (Data(json.utf8), HTTPURLResponse(url: URL(string: "https://api.example.test")!, statusCode: status, httpVersion: nil, headerFields: nil)!)
    }
}

private final class Box<T>: @unchecked Sendable {
    var value: T?
    init(_ value: T? = nil) { self.value = value }
}
