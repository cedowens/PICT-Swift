import XCTest

#if !canImport(ObjectiveC)
public func allTests() -> [XCTestCaseEntry] {
    return [
        testCase(pict_SwiftTests.allTests),
    ]
}
#endif
