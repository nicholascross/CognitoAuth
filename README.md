# CognitoAuth

A simple cognito SRP authenticator.  This was made mainly for testing purposes and may not be suitable for production usage.  A better option for production usage is probably [soto-cognito-authentication-kit](https://github.com/soto-project/soto-cognito-authentication-kit) if you don't mind the additional dependencies.

## Usage example

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

## Acknlowedgements

The [hard part](Sources/CognitoAuth/SRP.swift) of this process was done by [Adam Fowler](https://github.com/adam-fowler).  I cannot locate the original source repository.
