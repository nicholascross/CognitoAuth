import Foundation

struct PasswordVerifierParameters: Decodable {
    private enum CodingKeys: String, CodingKey {
        case salt = "SALT"
        case secretBlock = "SECRET_BLOCK"
        case srpB = "SRP_B"
        case username = "USERNAME"
        case userID = "USER_ID_FOR_SRP"
    }
    
    let salt: String
    let secretBlock: String
    let srpB: String
    let username: String
    let userID: String
}
