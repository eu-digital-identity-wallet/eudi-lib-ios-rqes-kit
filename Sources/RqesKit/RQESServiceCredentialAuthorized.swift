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
import RQESLib
import CommonCrypto
import X509
import SwiftASN1

public typealias SigningAlgorithmOID = RQESLib.SigningAlgorithmOID
/// The authorized credential is used to sign the documents. The list of documents that will be signed using the authorized credential are the documents
/// that were passed to the ``RQESServiceAuthorizedProtocol.`` method.
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
    var outputURLs: [URL]
    
    public init(
        rqes: RQES,
        clientConfig: CSCClientConfig,
        credentialInfo: CredentialInfo,
        credentialAccessToken: String,
        documents: [Document],
        calculateHashResponse: DocumentDigests,
        hashAlgorithmOID: HashAlgorithmOID,
        defaultSigningAlgorithmOID: SigningAlgorithmOID?,
        fileExtension: String,
        outputURLs: [URL]
    ) {
        self.rqes = rqes
        self.clientConfig = clientConfig
        self.credentialInfo = credentialInfo
        self.credentialAccessToken = credentialAccessToken
        self.documents = documents
        self.calculateHashResponse = calculateHashResponse
        self.hashAlgorithmOID = hashAlgorithmOID
        self.defaultSigningAlgorithmOID = defaultSigningAlgorithmOID
        self.fileExtension = fileExtension
        self.outputURLs = outputURLs
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
    public func signDocuments(signAlgorithmOID: SigningAlgorithmOID? = nil) async throws -> [Document] {
        // STEP 12: Sign the calculated hash with the credential
        guard let signAlgo = signAlgorithmOID ?? defaultSigningAlgorithmOID else {
            throw NSError(
                domain: "RQES",
                code: 0,
                userInfo: [NSLocalizedDescriptionKey: "No signing algorithm provided"]
            )
        }
        
        let signHashRequest: SignHashRequest = .init(
            credentialID: credentialInfo.credentialID,
            hashes: try DocumentDigests.init(digests: calculateHashResponse.hashes, output: .base64).hashes,
            hashAlgorithmOID: hashAlgorithmOID,
            signAlgo: signAlgo,
            operationMode: "S"
        )
        
        let signHashResponse = try await rqes.signHash(request: signHashRequest, accessToken: credentialAccessToken)
        guard let signatures = signHashResponse.signatures else {
            throw NSError(
                domain: "RQES",
                code: 0,
                userInfo: [NSLocalizedDescriptionKey: "No signatures provided"]
            )
        }
        
        // STEP 13: Create the signed documents locally
        // R5: Using createSignedDocuments method which works locally without base64 data or access tokens
        try await rqes.createSignedDocuments(signatures: signatures)
        // Return the signed documents from their output paths
        let documentsWithSignature = documents.enumerated().map { i, document in
            // The signed documents are created at the output paths specified during hash calculation
            Document(id: document.id, fileURL: outputURLs[i])
        }
        
        return documentsWithSignature
    }
}
