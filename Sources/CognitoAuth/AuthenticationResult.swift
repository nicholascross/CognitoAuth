import Foundation

enum AuthenticationResult {
    case srpChallenge(SRPChallenge)
    case mfaChallenge(MFAChallenge)
    case newPasswordChallenge(NewPasswordChallenge)
    case authenticated(AuthTokens)
}
