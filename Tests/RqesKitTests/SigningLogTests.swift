import Foundation
import MdocDataModel18013
import RQESLib
import Testing
@testable import RqesKit

private actor RecordingTransactionLogger: TransactionLogger {
    var entries: [TransactionEntry] = []
    let shouldThrow: Bool

    init(shouldThrow: Bool = false) { self.shouldThrow = shouldThrow }

    func log(transaction: TransactionEntry) async throws {
        entries.append(transaction)
        if shouldThrow { throw CocoaError(.fileWriteUnknown) }
    }
}

@Test func signingLogRecordsDocumentsAndNormalizesDigests() async throws {
    let output = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try Data([1, 2, 3]).write(to: output)
    defer { try? FileManager.default.removeItem(at: output) }
    let logger = RecordingTransactionLogger()
    let log = RQESSigningLog(
        logger: logger,
        certificateIdentifier: "1234",
        serviceName: MultiLangString(content: "Signing service"),
        documents: [
            Document(id: "first", fileURL: URL(fileURLWithPath: "/input/contract.pdf")),
            Document(id: "second", fileURL: URL(fileURLWithPath: "/input/form.pdf"))
        ],
        hashes: ["-_8", "AQID"],
        outputURLs: [output]
    )
    await log.record(result: .completed)
    let entries = await logger.entries
    #expect(entries.count == 2)
    guard case .signingSealing(let first) = entries[0],
          case .signingSealing(let second) = entries[1] else {
        Issue.record("Expected signing transactions")
        return
    }
    #expect(first.transactionResult == .completed)
    #expect(first.reasonOfNoncompletion == nil)
    #expect(first.certificateIdentifier == "1234")
    #expect(first.dtbsr == "+/8=")
    #expect(first.fileIdentifier == "first")
    #expect(first.fileName == "contract.pdf")
    #expect(first.fileSize == "3")
    #expect(first.interactingPartyName?.content == "Signing service")
    #expect(first.signingTransactionIdentifier == second.signingTransactionIdentifier)
    #expect(first.transactionIdentifier != second.transactionIdentifier)
    #expect(second.dtbsr == "AQID")
    #expect(second.fileSize == nil)
}

@Test func signingLogContinuesAfterStorageFailure() async {
    let logger = RecordingTransactionLogger(shouldThrow: true)
    let log = RQESSigningLog(
        logger: logger, certificateIdentifier: nil, serviceName: nil,
        documents: [Document(id: "a", fileURL: URL(fileURLWithPath: "/missing")),
                    Document(id: "b", fileURL: URL(fileURLWithPath: "/missing"))],
        hashes: ["invalid!"], outputURLs: []
    )
    await log.record(result: .notCompleted, reason: "Signing failed")
    let entries = await logger.entries
    #expect(entries.count == 2)
    for entry in entries {
        guard case .signingSealing(let value) = entry else { continue }
        #expect(value.transactionResult == .notCompleted)
        #expect(value.reasonOfNoncompletion == "Signing failed")
        #expect(value.dtbsr == nil)
        #expect(value.fileSize == nil)
    }
}

@Test func signingFailureIsLoggedWithoutReplacingTheError() async throws {
    let config = CSCClientConfig(
        OAuth2Client: .init(clientId: "test", clientSecret: "test"),
        authFlowRedirectionURI: "https://example.com/callback", rsspId: ""
    )
    let credential = try JSONDecoder().decode(RqesKit.CredentialInfo.self, from: Data("""
    {
        "credentialID": "credential", "key": {"status": "enabled", "algo": [], "len": 2048},
        "cert": {"status": "valid", "certificates": [], "issuerDN": "issuer",
                 "serialNumber": "1234", "subjectDN": "subject", "validFrom": "", "validTo": ""}
    }
    """.utf8))
    let logger = RecordingTransactionLogger(shouldThrow: true)
    let service = await RQESService(clientConfig: config, transactionLogger: logger)
    #expect(service.transactionLogger === logger)
    let authorized = RQESServiceCredentialAuthorized(
        rqes: service.rqes, clientConfig: config, credentialInfo: credential,
        credentialAccessToken: "test", documents: [Document(id: "contract", fileURL: URL(fileURLWithPath: "/contract.pdf"))],
        calculateHashResponse: DocumentDigests(hashes: ["AQID"]), hashAlgorithmOID: .SHA256,
        defaultSigningAlgorithmOID: nil, fileExtension: ".pdf", outputURLs: [], transactionLogger: logger
    )
    for _ in 0..<2 {
        do {
            _ = try await authorized.signDocuments()
            Issue.record("Expected missing signing algorithm error")
        } catch {
            #expect(error.localizedDescription == "No signing algorithm provided")
        }
    }
    let entries = await logger.entries
    #expect(entries.count == 2)
    #expect(entries.allSatisfy { $0.transactionResult == .notCompleted })
    #expect(entries.allSatisfy { $0.reasonOfNoncompletion == "No signing algorithm provided" })
    #expect(entries[0].transactionIdentifier != entries[1].transactionIdentifier)
}
