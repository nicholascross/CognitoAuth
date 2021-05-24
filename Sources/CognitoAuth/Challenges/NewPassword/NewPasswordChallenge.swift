import Foundation

struct NewPasswordChallenge {
    let requiredAttributes: [String]
    let userAttributes: [String: String]
    let session: String
}