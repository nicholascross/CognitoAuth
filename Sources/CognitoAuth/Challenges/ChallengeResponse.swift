import Foundation

struct ChallengeResponse<Responses: Encodable>: Encodable {
    private enum CodingKeys: String, CodingKey {
        case challengeResponses = "ChallengeResponses"
        case challengeType = "ChallengeName"
        case clientId = "ClientId"
        case session = "Session"
    }
    
    let challengeResponses: Responses
    let challengeType: String
    let clientId: String
    let session: String?
}
 
