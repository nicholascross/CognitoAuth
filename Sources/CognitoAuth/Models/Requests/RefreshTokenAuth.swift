import Foundation

struct RefreshTokenAuth: Encodable {
    enum CodingKeys: String, CodingKey {
        case authFlow = "AuthFlow"
        case authParameters = "AuthParameters"
        case clientId = "ClientId"
    }

    private let authFlow: String = "REFRESH_TOKEN_AUTH"
    let authParameters: RefreshTokenParameters
    let clientId: String
}

struct RefreshTokenParameters: Encodable {
    enum CodingKeys: String, CodingKey {
        case refreshToken = "REFRESH_TOKEN"
        case secretHash = "SECRET_HASH"
    }

    let refreshToken: String
    let secretHash: String
}
