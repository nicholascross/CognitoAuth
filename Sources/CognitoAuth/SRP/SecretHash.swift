import Foundation
import Crypto

struct SecretHash {
    let clientId: String
    let clientSecret: String
    let username: String

    var hashString: String {
        let message = Data((username + clientId).utf8)
        let key = SymmetricKey(data: Data(clientSecret.utf8))
        let secretHash = HMAC<SHA256>.authenticationCode(for: message, using: key)
        return Data(secretHash).base64EncodedString()
    }
}