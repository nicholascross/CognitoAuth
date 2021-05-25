import Foundation

enum RequestTarget: String {
    case initiateAuthTarget = "AWSCognitoIdentityProviderService.InitiateAuth"
    case respondToAuthChallenge = "AWSCognitoIdentityProviderService.RespondToAuthChallenge"
}
