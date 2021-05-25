import Foundation

public enum ChallengeType: String, Codable {
    case smsMFA = "SMS_MFA"
    case softwareTokenMFA = "SOFTWARE_TOKEN_MFA"
    case selectMFAType = "SELECT_MFA_TYPE"
    case mfaSetup = "MFA_SETUP"
    case passwordVerifier = "PASSWORD_VERIFIER"
    case customerChallenge = "CUSTOM_CHALLENGE"
    case deviceSRPAuth = "DEVICE_SRP_AUTH"
    case devicePasswordVerifier = "DEVICE_PASSWORD_VERIFIER"
    case adminNoSRPAuth = "ADMIN_NO_SRP_AUTH"
    case newPasswordRequired = "NEW_PASSWORD_REQUIRED"
}
