import Foundation

struct Challenge<ParameterType: Decodable>: Decodable {
    private enum CodingKeys: String, CodingKey {
        case challengeType = "ChallengeName"
        case challengeParameters = "ChallengeParameters"
        case session = "Session"
    }
    let challengeType: ChallengeType
    let challengeParameters: ParameterType
    let session: String?
}
