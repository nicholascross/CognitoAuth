# CognitoAuth

Usage example

```swift
import Foundation
import CognitoAuth

let config = AuthConfig(
    endpointURL: URL(string: "https://cognito-idp.ap-southeast-2.amazonaws.com")!,
    clientId: "theclientid",
    clientSecret: "thelcientsecret",
    poolId: "1Q2Q3Q4Q"
)

let username = "ausername"
let password = "apassword"
let service = AuthService(config: config, username: username, password: password)

public final class AuthDelegate: AuthServiceDelegate {
    public func authService(_ service: AuthService, authenticationSuccessful tokens: AuthTokens) {
        print("access: \(tokens.accessToken)")
        print("id: \(tokens.idToken)")
        print("refresh: \(tokens.refreshToken)")
    }

    public func authService(_ service: AuthService, authenticationFailedWithError error: Error) {
        print("failed: \(error)")
    }

    public func authService(_ service: AuthService, provideMFACode: (String) -> ()) {
        print("enter mfa code:")
        guard let code = readLine() else {
            print("code unavailable")
            return
        }
        provideMFACode(code)
    }
}

let delegate = AuthDelegate()

service.delegate = delegate

service.authenticate()
```
