# TiswaVerify for iOS

Verify with Tiswa from an iPhone app. The package starts the check with PKCE and opens the Tiswa app, or the web sheet in `ASWebAuthenticationSession` when Tiswa isn't installed. The shopper comes back to your app with a one-time code.

Docs: https://developers.tiswa.app/developers/mobile

## Install

Swift Package Manager: `https://github.com/samifathi26/tiswa-verify-swift`, from `0.1.0`. iOS 15 or later.

## Use

```swift
import TiswaVerify

let tiswa = TiswaVerify(configuration: .init(
    publishableKey: "tsw_pk_live_…",
    program: "prg_…",
    redirectURI: URL(string: "https://shop.example.sa/tiswa/app-callback")!))

let result = try await tiswa.verify(nonce: cart.id)
// Send result.code, result.codeVerifier and result.redirectURI to your backend,
// which calls POST /v1/oauth/token with the secret key.
```

Pass every URL your app opens to `TiswaVerify.handle(_:)` (`onOpenURL`, `scene(_:openURLContexts:)`, and `scene(_:continue:)` for universal links).

Register the redirect for an **iOS** client in the Tiswa console. If `verify` throws, carry on at full price.

## Test

```bash
swift test
```

## Licence

MIT. See [LICENSE](LICENSE).
