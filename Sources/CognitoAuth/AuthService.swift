import Foundation
import Crypto
import BigNum

public final class AuthService {

    public weak var delegate: AuthServiceDelegate?

    private let config: AuthConfig
    private let username: String
    private let srp: SRP<SHA256>
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

            if let passwordChallenge: Challenge<PasswordVerifierParameters> = responseData.decode() {
                session = passwordChallenge.session
                userId = passwordChallenge.challengeParameters.userID
                completion(.success(.srpChallenge(try SRPChallenge(parameters: passwordChallenge.challengeParameters))))

            } else if let mfaChallenge: Challenge<MultiFactorAuthParamaters> = responseData.decode() {
                guard let session = session else {
                    completion(.failure(AuthServiceError.missingSession))
                    return
                }

                completion(.success(.mfaChallenge(try MFAChallenge(parameters: mfaChallenge.challengeParameters, session: session))))

            } else if let authResult: AuthResult = responseData.decode() {
                let tokens = authResult.authenticationResult
                completion(.success(.authenticated(
                        AuthTokens(
                                accessToken: tokens.accessToken,
                                idToken: tokens.idToken,
                                refreshToken: tokens.refreshToken
                        )
                )))

            } else if let newPasswordChallenge: Challenge<NewPasswordParameters> = responseData.decode(),
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
            handleSRPChallenge(challenge, password: password)

        case let .success(.mfaChallenge(challenge)):
            handleMFAChallenge(challenge)

        case let .success(.newPasswordChallenge(challenge)):
            handleNewPasswordChallenge(challenge)

        case let .success(.authenticated(tokens)):
            self.delegate?.authService(self, authenticationSuccessful: tokens)

        case let .failure(error):
            self.delegate?.authService(self, authenticationFailedWithError: error)

        }
    }

    private func handleNewPasswordChallenge(_ challenge: NewPasswordChallenge) -> ()? {
        self.delegate?.authService(self,
                        requiredAttributes: challenge.requiredAttributes,
                        userAttributes: challenge.userAttributes,
                        provideNewPassword: { password, userAttributes in
            do {
                execute(request: try respondToNewPasswordChallenge(session: challenge.session, password: password, userAttributes: userAttributes)) {
                    self.handleResult($0)
                }
            } catch {
                self.delegate?.authService(self, authenticationFailedWithError: error)
            }
        })
    }

    private func handleMFAChallenge(_ challenge: MFAChallenge) -> ()? {
        self.delegate?.authService(self, provideMFACode: { code in
            do {
                execute(request: try respondToMFAChallenge(session: challenge.session, code: code)) {
                    self.handleResult($0)
                }
            } catch {
                self.delegate?.authService(self, authenticationFailedWithError: error)
            }
        })
    }

    private func handleSRPChallenge(_ challenge: SRPChallenge, password: String?) {
        do {
            guard let password = password,
                  let clientProof = srp.getPasswordAuthenticationKey(
                          username: config.poolId + challenge.userId,
                          password: password,
                          B: challenge.srpB,
                          salt: challenge.salt
                  ) else {
                throw AuthServiceError.unableToGenerateClientProofKey
            }

            let key = SymmetricKey(data: clientProof)
            execute(request: try respondToSRPChallenge(challenge: challenge, clientProofKey: key)) {
                self.handleResult($0)
            }
        } catch {
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

        let builder = RequestBuilder<InitiateAuth>(config: config)
        builder.body = requestBody
        builder.target = .initiateAuthTarget
        return try builder.request()
    }

    private func refreshTokenAuthRequest(token: String) throws -> URLRequest {
        let requestBody = RefreshTokenAuth(
            authParameters: RefreshTokenParameters(
                refreshToken: token,
                secretHash: secretHash.hashString
            ),
            clientId: config.clientId
        )

        let builder = RequestBuilder<RefreshTokenAuth>(config: config)
        builder.body = requestBody
        builder.target = .initiateAuthTarget
        return try builder.request()
    }

    private func respondToSRPChallenge(challenge: SRPChallenge, clientProofKey: SymmetricKey) throws -> URLRequest {
        let timestamp = dateFormatter.string(from: Date())

        let message = Data("\(config.poolId)\(challenge.userId)".utf8) + challenge.secretBlockData + Data(timestamp.utf8)
        let claim = HMAC<SHA256>.authenticationCode(for: message, using:  clientProofKey)

        let requestBody = ChallengeResponse<SRPChallengeResponse>(
            challengeResponses: SRPChallengeResponse(
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

        let builder = RequestBuilder<ChallengeResponse<SRPChallengeResponse>>(config: config)
        builder.body = requestBody
        builder.target = .respondToAuthChallenge
        return try builder.request()
    }

    private func respondToMFAChallenge(session: String, code: String) throws -> URLRequest {
        let requestBody = ChallengeResponse<MFAChallengeResponse>(
            challengeResponses: MFAChallengeResponse(username: username, secretHash: secretHash.hashString, code: code),
            challengeType: ChallengeType.smsMFA.rawValue,
            clientId: config.clientId,
            session: session
        )

        let builder = RequestBuilder<ChallengeResponse<MFAChallengeResponse>>(config: config)
        builder.body = requestBody
        builder.target = .respondToAuthChallenge
        return try builder.request()
    }

    private func respondToNewPasswordChallenge(session: String, password: String, userAttributes: [String: String]) throws -> URLRequest {
        let requestBody = ChallengeResponse<NewPasswordChallengeResponse>(
            challengeResponses: NewPasswordChallengeResponse(
                    username: username,
                    secretHash: secretHash.hashString,
                    password: password,
                    userAttributes: userAttributes
            ),
            challengeType: ChallengeType.newPasswordRequired.rawValue,
            clientId: config.clientId,
            session: session
        )

        let builder = RequestBuilder<ChallengeResponse<NewPasswordChallengeResponse>>(config: config)
        builder.body = requestBody
        builder.target = .respondToAuthChallenge
        return try builder.request()
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

private enum Constants {
    static let requestDateFormat = "EEE MMM d HH:mm:ss 'UTC' yyyy"
    static let requestTimeZone = "UTC"
}

private enum RequestError: String, Error {
    case dataMissing
}

private extension Data {
    func decode<DecodableType: Decodable>(decoder: JSONDecoder = JSONDecoder()) -> DecodableType? {
        return try? decoder.decode(DecodableType.self, from: self)
    }
}