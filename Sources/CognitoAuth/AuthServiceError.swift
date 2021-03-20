import Foundation

public enum AuthServiceError: Error {
    case unhandledChallengeType
    case invalidSalt(String)
    case invalidSecret(String)
    case invalidSRPB(String)
    case invalidDeliveryMedium
    case unableToGenerateClientProofKey
    case missingSession
}
