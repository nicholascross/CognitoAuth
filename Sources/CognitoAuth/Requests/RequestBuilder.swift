import Foundation

final class RequestBuilder<BodyType: Encodable> {
    private let config: AuthConfig

    var target: RequestTarget = .respondToAuthChallenge
    var body: BodyType?

    init(config: AuthConfig) {
        self.config = config
    }

    func request() throws -> URLRequest {
        var request = URLRequest(url: URL(string: "\(config.endpointURL.absoluteString)")!)
        request.setValue(target.rawValue, forHTTPHeaderField: Headers.requestTarget)
        request.setValue(Constants.contentType, forHTTPHeaderField: Headers.contentType)

        if let body = body {
            request.httpBody = try JSONEncoder().encode(body)
        }

        request.httpMethod = Constants.requestMethod
        return request
    }
}

private enum Constants {
    static let contentType = "application/x-amz-json-1.1"
    static let requestMethod = "POST"
}

private enum Headers {
    static let requestTarget = "X-Amz-Target"
    static let contentType = "Content-Type"
}