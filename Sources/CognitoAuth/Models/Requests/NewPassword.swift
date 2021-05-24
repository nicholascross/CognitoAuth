import Foundation

struct NewPassword: Encodable {
    private enum CodingKeys: String, CodingKey {
        case username = "USERNAME"
        case secretHash = "SECRET_HASH"
        case password =  "NEW_PASSWORD"
        case userAttributes =  "userAttributes"
    }

    let username: String
    let secretHash: String
    let password: String
    let userAttributes: [String: String]?

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(username, forKey: .username)
        try container.encode(secretHash, forKey: .secretHash)
        try container.encode(password, forKey: .password)

        if let userAttributes = userAttributes {
            var container = encoder.container(keyedBy: DynamicKey.self)
            try userAttributes.forEach { key, value in
                guard let dynamicKey = DynamicKey(stringValue: "userAttributes.\(key)") else { return }
                try container.encode(value, forKey: dynamicKey)
            }
        }
    }
}

private struct DynamicKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        self.intValue = nil
    }

    init?(intValue: Int) {
        self.stringValue = "\(intValue)"
        self.intValue = intValue
    }
}