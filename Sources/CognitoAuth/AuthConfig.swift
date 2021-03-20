import Foundation

public struct AuthConfig {
    public let endpointURL: URL
    public let clientId: String
    public let clientSecret: String
    public let poolId: String

    public init(endpointURL: URL, clientId: String, clientSecret: String, poolId: String) {
        self.endpointURL = endpointURL
        self.clientId = clientId
        self.clientSecret = clientSecret
        self.poolId = poolId
    }
}
