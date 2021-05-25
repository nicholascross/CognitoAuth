import Foundation
import BigNum

struct SRPChallenge {
    let salt: [UInt8]
    let secretBlock: String
    let secretBlockData: Data
    let srpB: BigNum
    let username: String
    let userId: String

    init(parameters: PasswordVerifierParameters) throws {
        guard let salt = BigNum(hex: parameters.salt)?.bytes else { throw AuthServiceError.invalidSalt(parameters.salt) }
        guard let data = Data(base64Encoded: parameters.secretBlock) else { throw AuthServiceError.invalidSecret(parameters.secretBlock) }
        guard let srpB = BigNum(hex: parameters.srpB) else { throw AuthServiceError.invalidSRPB(parameters.srpB) }

        self.salt = salt
        self.secretBlock = parameters.secretBlock
        self.secretBlockData = data
        self.srpB = srpB
        self.username = parameters.username
        self.userId = parameters.userID
    }
}
