import Foundation

struct InitiateAuth: Encodable {
    enum CodingKeys: String, CodingKey {
        case authFlow = "AuthFlow"
        case authParameters = "AuthParameters"
        case clientId = "ClientId"
    }
    
    private let authFlow: String = "USER_SRP_AUTH"
    let authParameters: AuthParameters
    let clientId: String
}

struct AuthParameters: Encodable {
    enum CodingKeys: String, CodingKey {
        case username = "USERNAME"
        case password = "PASSWORD"
        case srpA = "SRP_A"
        case secretHash = "SECRET_HASH"
    }
    
    let username: String
    let password: String
    let srpA: String
    let secretHash: String
}
