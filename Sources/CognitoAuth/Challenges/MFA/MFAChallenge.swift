import Foundation

struct MFAChallenge {
    let destination: String
    let session: String

    init(parameters: MultiFactorAuthParamaters, session: String) throws {
        guard parameters.deliveryMedium == .sms else { throw AuthServiceError.invalidDeliveryMedium }

        self.destination = parameters.deliveryDestination
        self.session = session
    }
}
