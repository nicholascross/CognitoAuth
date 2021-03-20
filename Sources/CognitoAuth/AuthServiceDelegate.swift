import Foundation

public protocol AuthServiceDelegate: AnyObject {
    func authService(_ service: AuthService, authenticationSuccessful tokens: AuthTokens)
    func authService(_ service: AuthService, authenticationFailedWithError error: Error)
    func authService(_ service: AuthService, provideMFACode: (String) -> ())
}
