import Foundation

struct NewPasswordParameters: Decodable {
    private enum CodingKeys: String, CodingKey {
        case requiredAttributes
        case userAttributes
    }

    let requiredAttributes: [String]
    let userAttributes: [String: String]

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if let rawRequiredAttributes: Data = try container.decode(String.self, forKey: .requiredAttributes).data(using: .utf8) {
            requiredAttributes = try JSONDecoder().decode([String].self, from: rawRequiredAttributes)
        } else {
            requiredAttributes = []
        }

        if let rawUserAttributes: Data = try container.decode(String.self, forKey: .userAttributes).data(using: .utf8) {
            userAttributes = try JSONDecoder().decode([String: String].self, from: rawUserAttributes)
        } else {
            userAttributes = [:]
        }
    }
}