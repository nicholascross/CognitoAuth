import Foundation

struct MFAChallengeResponse: Encodable {
    private enum CodingKeys: String, CodingKey {
        case username = "USERNAME"
        case secretHash = "SECRET_HASH"
        case code =  "SMS_MFA_CODE"
    }
    
    let username: String
    let secretHash: String
    let code: String
}
