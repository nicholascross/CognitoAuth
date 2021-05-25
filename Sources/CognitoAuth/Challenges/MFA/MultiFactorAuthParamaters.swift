import Foundation

struct MultiFactorAuthParamaters: Decodable {
    private enum CodingKeys: String, CodingKey {
        case deliveryMedium = "CODE_DELIVERY_DELIVERY_MEDIUM"
        case deliveryDestination = "CODE_DELIVERY_DESTINATION"
    }
    
    let deliveryMedium: DeliveryMedium
    let deliveryDestination: String
}

enum DeliveryMedium: String, Decodable {
    case sms = "SMS"
}
