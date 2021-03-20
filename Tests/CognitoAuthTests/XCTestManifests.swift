import XCTest

#if !canImport(ObjectiveC)
public func allTests() -> [XCTestCaseEntry] {
    return [
        testCase(CognitoAuthTests.allTests),
    ]
}
#endif
