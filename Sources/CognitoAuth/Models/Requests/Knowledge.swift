import Foundation

struct Knowledge: Encodable {
    private enum CodingKeys: String, CodingKey {
        case passwordClaimSecretBlock = "PASSWORD_CLAIM_SECRET_BLOCK"
        case username = "USERNAME"
        case secretHash = "SECRET_HASH"
        case passwordClaimSignature = "PASSWORD_CLAIM_SIGNATURE"
        case timestamp = "TIMESTAMP"
    }
    
    let passwordClaimSecretBlock: String
    let username: String
    let secretHash: String
    let passwordClaimSignature: String
    let timestamp: String
}
