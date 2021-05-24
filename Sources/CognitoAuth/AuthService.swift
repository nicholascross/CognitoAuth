import Foundation
import Crypto
import BigNum

public final class AuthService {

    private let config: AuthConfig
    private let username: String
    private let srp: SRP<SHA256>
    public weak var delegate: AuthServiceDelegate?
    private var session: String?
    private var userId: String?

    public init(config: AuthConfig, username: String) {
        self.config = config
        self.username = username
        self.srp = SRP<SHA256>()
    }

    public func authenticateWithPassword(_ password: String) {
        do {
            execute(request: try initiateAuthRequest(password: password, srpA: srp.A.hex)) {
                self.handleResult($0, password: password)
            }
        } catch {
            self.delegate?.authService(self, authenticationFailedWithError: error)
        }
    }

    public func authenticateWithRefreshToken(_ refreshToken: String) {
        do {
            execute(request: try refreshTokenAuthRequest(token: refreshToken)) {
                self.handleResult($0)
            }
        } catch {
            self.delegate?.authService(self, authenticationFailedWithError: error)
        }
    }

    private func execute(request: URLRequest, completion: @escaping (Result<AuthenticationResult, Error>) -> Void) {
        let task = URLSession.shared.dataTask(with: request) { (data, response, error) in
            self.handleResponse(data: data, response: response, error: error, completion: completion)
        }

        task.resume()
    }

    private func handleResponse(data: Data?, response: URLResponse?, error: Error?, completion: (Result<AuthenticationResult, Error>) -> Void) {
        do {
            guard let responseData = data else {
                throw RequestError.dataMissing
            }

            if let passwordChallenge = try? JSONDecoder().decode(Challenge<PasswordVerifierParameters>.self, from: responseData) {
                session = passwordChallenge.session
                userId = passwordChallenge.challengeParameters.userID
                completion(.success(.srpChallenge(try SRPChallenge(parameters: passwordChallenge.challengeParameters))))
            } else if let mfaChallenge = try? JSONDecoder().decode(Challenge<MultiFactorAuthParamaters>.self, from: responseData) {
                guard let session = session else {
                    completion(.failure(AuthServiceError.missingSession))
                    return
                }
                completion(.success(.mfaChallenge(try MFAChallenge(parameters: mfaChallenge.challengeParameters, session: session))))
            } else if let authResult = try? JSONDecoder().decode(AuthResult.self, from: responseData) {
                let tokens = authResult.authenticationResult
                completion(.success(.authenticated(AuthTokens(accessToken: tokens.accessToken, idToken: tokens.idToken, refreshToken: tokens.refreshToken))))
            } else if let newPasswordChallenge = try? JSONDecoder().decode(Challenge<NewPasswordParameters>.self, from: responseData),
                      newPasswordChallenge.challengeType == .newPasswordRequired {
                session = newPasswordChallenge.session
                guard let session = session else {
                    completion(.failure(AuthServiceError.missingSession))
                    return
                }

                completion(.success(.newPasswordChallenge(
                        NewPasswordChallenge(
                                requiredAttributes: newPasswordChallenge.challengeParameters.requiredAttributes,
                                userAttributes: newPasswordChallenge.challengeParameters.userAttributes,
                                session: session
                        )
                )))
            } else {
                completion(.failure(AuthServiceError.unhandledChallengeType))
            }
        } catch {
            completion(.failure(error))
        }
    }

    private func handleResult(_ result: Result<AuthenticationResult, Error>, password: String? = nil) {
        switch result {
        case let .success(.srpChallenge(challenge)):
            do {
                guard let password = password,
                      let clientProof = srp.getPasswordAuthenticationKey(username: config.poolId + challenge.userId, password: password, B: challenge.srpB, salt: challenge.salt) else {
                    throw AuthServiceError.unableToGenerateClientProofKey
                }

                let key = SymmetricKey(data: clientProof)
                execute(request: try verifyKnowledgeRequest(challenge: challenge, clientProofKey: key)) {
                    self.handleResult($0)
                }
            } catch {
                self.delegate?.authService(self, authenticationFailedWithError: error)
            }

        case let .success(.mfaChallenge(challenge)):
            self.delegate?.authService(self, provideMFACode: { code in
                do {
                    execute(request: try verifyPossessionRequest(session: challenge.session, code: code)) {
                        self.handleResult($0)
                    }
                } catch {
                    self.delegate?.authService(self, authenticationFailedWithError: error)
                }
            })

        case let .success(.newPasswordChallenge(challenge)):
            self.delegate?.authService(self,
                            requiredAttributes: challenge.requiredAttributes,
                            userAttributes: challenge.userAttributes,
                            provideNewPassword: { password, userAttributes in
                do {
                    execute(request: try changePasswordRequest(session: challenge.session, password: password, userAttributes: userAttributes)) {
                        self.handleResult($0)
                    }
                } catch {
                    self.delegate?.authService(self, authenticationFailedWithError: error)
                }
            })

        case let .success(.authenticated(tokens)):
            self.delegate?.authService(self, authenticationSuccessful: tokens)

        case let .failure(error):
            self.delegate?.authService(self, authenticationFailedWithError: error)

        }
    }

    private func initiateAuthRequest(password: String, srpA: String) throws -> URLRequest {
        let requestBody = InitiateAuth(
            authParameters: AuthParameters(
                username: username,
                password: password,
                srpA: srpA,
                secretHash: secretHash.hashString
            ),
            clientId: config.clientId
        )

        return request(target: Constants.initiateAuthTarget, body: try JSONEncoder().encode(requestBody))
    }

    private func refreshTokenAuthRequest(token: String) throws -> URLRequest {
        let requestBody = RefreshTokenAuth(
            authParameters: RefreshTokenParameters(
                refreshToken: token,
                secretHash: secretHash.hashString
            ),
            clientId: config.clientId
        )

        return request(target: Constants.initiateAuthTarget, body: try JSONEncoder().encode(requestBody))
    }

    private func verifyKnowledgeRequest(challenge: SRPChallenge, clientProofKey: SymmetricKey) throws -> URLRequest {
        let timestamp = dateFormatter.string(from: Date())

        let message = Data("\(config.poolId)\(challenge.userId)".utf8) + challenge.secretBlockData + Data(timestamp.utf8)
        let claim = HMAC<SHA256>.authenticationCode(for: message, using:  clientProofKey)

        let requestBody = ChallengeResponse<Knowledge>(
            challengeResponses: Knowledge(
                passwordClaimSecretBlock: challenge.secretBlock,
                username: challenge.userId,
                secretHash: secretHash.hashString,
                passwordClaimSignature: Data(claim).base64EncodedString(),
                timestamp: timestamp
            ),
            challengeType: ChallengeType.passwordVerifier.rawValue,
            clientId: config.clientId,
            session: nil
        )

        return request(target: Constants.verifyKnowledgeTarget, body: try JSONEncoder().encode(requestBody))
    }

    private func verifyPossessionRequest(session: String, code: String) throws -> URLRequest {
        let requestBody = ChallengeResponse<Possession>(
            challengeResponses: Possession(username: username, secretHash: secretHash.hashString, code: code),
            challengeType: ChallengeType.smsMFA.rawValue,
            clientId: config.clientId,
            session: session
        )

        return request(target: Constants.verifyPossessionTarget, body: try JSONEncoder().encode(requestBody))
    }

    private func changePasswordRequest(session: String, password: String, userAttributes: [String: String]) throws -> URLRequest {
        let requestBody = ChallengeResponse<NewPassword>(
            challengeResponses: NewPassword(username: username, secretHash: secretHash.hashString, password: password, userAttributes: userAttributes),
            challengeType: ChallengeType.newPasswordRequired.rawValue,
            clientId: config.clientId,
            session: session
        )

        return request(target: Constants.newPasswordRequiredTarget, body: try JSONEncoder().encode(requestBody))
    }

    private func request(target: String, body: Data) -> URLRequest {
        var request = URLRequest(url: URL(string: "\(config.endpointURL.absoluteString)")!)
        request.setValue(target, forHTTPHeaderField: Headers.requestTarget)
        request.setValue(Constants.contentType, forHTTPHeaderField: Headers.contentType)
        request.httpBody = body
        request.httpMethod = Constants.requestMethod
        return request
    }

    private var secretHash: SecretHash {
        return SecretHash(clientId: config.clientId, clientSecret: config.clientSecret, username: userId ?? username)
    }

    private lazy var dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = Constants.requestDateFormat
        formatter.timeZone = TimeZone(identifier: Constants.requestTimeZone)
        return formatter
    }()


}

private enum AuthenticationResult {
    case srpChallenge(SRPChallenge)
    case mfaChallenge(MFAChallenge)
    case newPasswordChallenge(NewPasswordChallenge)
    case authenticated(AuthTokens)
}

private enum Constants {
    static let initiateAuthTarget = "AWSCognitoIdentityProviderService.InitiateAuth"
    static let verifyKnowledgeTarget = "AWSCognitoIdentityProviderService.RespondToAuthChallenge"
    static let verifyPossessionTarget = "AWSCognitoIdentityProviderService.RespondToAuthChallenge"
    static let newPasswordRequiredTarget = "AWSCognitoIdentityProviderService.RespondToAuthChallenge"
    static let contentType = "application/x-amz-json-1.1"
    static let requestMethod = "POST"
    static let requestDateFormat = "EEE MMM d HH:mm:ss 'UTC' yyyy"
    static let requestTimeZone = "UTC"
}

private enum Headers {
    static let requestTarget = "X-Amz-Target"
    static let contentType = "Content-Type"
}

private enum RequestError: String, Error {
    case dataMissing
}

private struct SRPChallenge {
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

private struct MFAChallenge {
    let destination: String
    let session: String

    init(parameters: MultiFactorAuthParamaters, session: String) throws {
        guard parameters.deliveryMedium == .sms else { throw AuthServiceError.invalidDeliveryMedium }

        self.destination = parameters.deliveryDestination
        self.session = session
    }
}

private struct NewPasswordChallenge {
    let requiredAttributes: [String]
    let userAttributes: [String: String]
    let session: String
}