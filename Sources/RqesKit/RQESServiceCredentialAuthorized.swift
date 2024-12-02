/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import Foundation
import RQES_LIBRARY
import CommonCrypto
import X509
import SwiftASN1

public typealias SigningAlgorithmOID = RQES_LIBRARY.SigningAlgorithmOID
/// The authorized credential is used to sign the documents. The list of documents that will be signed using the authorized credential are the documents
/// that were passed to the ``RQESServiceAuthorizedProtocol.getCredentialAuthorizationUrl`` method.
public class RQESServiceCredentialAuthorized: RQESServiceCredentialAuthorizedProtocol, @unchecked Sendable {
    var rqes: RQES
    var clientConfig: CSCClientConfig
    var credentialInfo: CredentialInfo
    var credentialAccessToken: String
    var documents: [Document]
    var calculateHashResponse: DocumentDigests
    var hashAlgorithmOID: HashAlgorithmOID
    var defaultSigningAlgorithmOID: SigningAlgorithmOID?
    var fileExtension: String
 
    public init(rqes: RQES, clientConfig: CSCClientConfig, credentialInfo: CredentialInfo, credentialAccessToken: String, documents: [Document], calculateHashResponse: DocumentDigests, hashAlgorithmOID: HashAlgorithmOID, defaultSigningAlgorithmOID: SigningAlgorithmOID?, fileExtension: String) {
        self.rqes = rqes
        self.clientConfig = clientConfig
        self.credentialInfo = credentialInfo
        self.credentialAccessToken = credentialAccessToken
        self.documents = documents
        self.calculateHashResponse = calculateHashResponse
        self.hashAlgorithmOID = hashAlgorithmOID
        self.defaultSigningAlgorithmOID = defaultSigningAlgorithmOID
        self.fileExtension = fileExtension
    }

    /// Signs the documents using the specified hash algorithm and certificates.
    /// 
    /// - Parameters:
    ///   - signAlgorithmOID: The object identifier (OID) of the algorithm to be used for signing. This parameter is optional.
    ///   - certificates: An array of X509 certificates to be used for signing. This parameter is optional.
    /// 
    /// - Returns: An array of signed documents.
    /// 
    /// The list of documents that will be signed using the authorized credential are the documents
    /// that were passed to the ``RQESServiceAuthorizedProtocol.getCredentialAuthorizationUrl`` method.
	public func signDocuments(signAlgorithmOID: SigningAlgorithmOID? = nil, certificates: [X509.Certificate]? = nil) async throws -> [Document] {
		// STEP 12: Sign the calculated hash with the credential
        guard let signAlgo = signAlgorithmOID ?? defaultSigningAlgorithmOID else { throw NSError(domain: "RQES", code: 0, userInfo: [NSLocalizedDescriptionKey: "No signing algorithm provided"]) }
		let signHashRequest = SignHashRequest(credentialID: credentialInfo.credentialID, hashes: calculateHashResponse.hashes, hashAlgorithmOID: hashAlgorithmOID, signAlgo: signAlgo, operationMode: "S")
		let signHashResponse = try await rqes.signHash(request: signHashRequest, accessToken: credentialAccessToken)
		let certs = certificates?.map(\.base64String) ?? credentialInfo.cert.certificates
		// STEP 13: Obtain the signed document
		let obtainSignedDocRequest = ObtainSignedDocRequest(documents: documents.map {	ObtainSignedDocRequest.Document(
			document: (try! Data(contentsOf: $0.fileURL)).base64EncodedString(), signatureFormat: SignatureFormat.P, conformanceLevel: ConformanceLevel.ADES_B_B, signedEnvelopeProperty: SignedEnvelopeProperty.ENVELOPED, container: "No") },
				endEntityCertificate: certs.first!, certificateChain: Array(certs.dropFirst()), hashAlgorithmOID: hashAlgorithmOID, date: calculateHashResponse.signatureDate, signatures: signHashResponse.signatures ?? [])
		let obtainSignedDocResponse = try await rqes.getSignedDocuments(request: obtainSignedDocRequest, accessToken: credentialAccessToken)

		let documentsWithSignature = obtainSignedDocResponse.documentWithSignature.enumerated().map { i, d in Document(id: documents[i].id, fileURL: try! RQESService.saveToTempFile(data: Data(base64Encoded: d)!, fileExtension: fileExtension)) }
        return documentsWithSignature
	}

}