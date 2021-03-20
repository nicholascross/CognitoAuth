import Foundation

struct AuthResult: Decodable {
    private enum CodingKeys: String, CodingKey {
        case authenticationResult = "AuthenticationResult"
    }
    
    let authenticationResult: AuthResultTokens
}

public struct AuthResultTokens: Decodable {
    private enum CodingKeys: String, CodingKey {
        case accessToken = "AccessToken"
        case expiresIn = "ExpiresIn"
        case idToken = "IdToken"
        case refreshToken = "RefreshToken"
    }
    
    public let accessToken: String
    public let expiresIn: Int
    public let idToken: String
    public let refreshToken: String

}
