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

/// The authorized service is used to access the user's credentials
public class RQESServiceAuthorized: RQESServiceAuthorizedProtocol, @unchecked Sendable {
    
    var rqes: RQES
    var clientConfig: CSCClientConfig
    var accessToken: String
    var calculateHashResponse: DocumentDigests?
    var documents: [Document]?
    var outputURLs: [URL]?
    var state: String
    var credentialInfo: CredentialInfo?
    var authorizationDetails: AuthorizationDetails?
    var hashAlgorithmOID: HashAlgorithmOID?
    var defaultHashAlgorithmOID: HashAlgorithmOID
    var defaultSigningAlgorithmOID: SigningAlgorithmOID?
    var fileExtension: String
    
    public init(
        _ rqes: RQES,
        clientConfig: CSCClientConfig,
        defaultHashAlgorithmOID: HashAlgorithmOID,
        defaultSigningAlgorithmOID: SigningAlgorithmOID?,
        fileExtension: String,
        state: String,
        accessToken: String
    ) {
        self.rqes = rqes
        self.clientConfig = clientConfig
        self.defaultHashAlgorithmOID = defaultHashAlgorithmOID
        self.defaultSigningAlgorithmOID = defaultSigningAlgorithmOID
        self.fileExtension = fileExtension
        self.state = state
        self.accessToken = accessToken
    }
    
    /// Retrieve the list of credentials
    /// - Returns: The list of credentials
    /// The credentials are the user's credentials that can be used to sign the documents.
    public func getCredentialsList() async throws -> [CredentialInfo] {
        // STEP 7: Request the list of credentials using the access token
        let requestDefault = CredentialsListRequest(credentialInfo: true, certificates: "chain", certInfo: true)
        let response = try await rqes.listCredentials(request: requestDefault, accessToken: accessToken)
        guard let credentialInfos = response.credentialInfos else { throw NSError(domain: "RQESKit", code: 0,  userInfo: [NSLocalizedDescriptionKey: "Missing Credential Info"] ) }
        return credentialInfos
    }
    
    /// Get the credential authorization URL
    /// - Parameters:
    ///   - credentialInfo: Information about the credential.
    ///   - documents: An array of documents that will be signed.
    ///   - hashAlgorithmOID: The object identifier (OID) of the hash algorithm to be used, optional.
    ///   - certificates: An optional array of X509 certificates.
    /// - Returns: The credential authorization URL
    /// The credential authorization URL is used to authorize the credential that will be used to sign the documents.
    public func getCredentialAuthorizationUrl(credentialInfo: CredentialInfo, documents: [Document], hashAlgorithmOID: HashAlgorithmOID? = nil, certificates: [X509.Certificate]? = nil) async throws -> URL {
        self.documents = documents
        self.credentialInfo = credentialInfo
        self.hashAlgorithmOID = hashAlgorithmOID ?? defaultHashAlgorithmOID
        let certs = certificates?.map(\.base64String) ?? credentialInfo.cert.certificates
        
        guard let algo = credentialInfo.key.algo.first else {
            throw NSError(
                domain: "Signing alogorithm error",
                code: 0,
                userInfo: [NSLocalizedDescriptionKey: "Failes to retrive list of supported signing algorithms"]
            )
        }
        defaultSigningAlgorithmOID = SigningAlgorithmOID(rawValue: algo)
        
        // STEP 9: calculate hashes
        let outputURLs = documents.map { _ in RQESService.getTempFileURL(fileExtension: fileExtension) }
        self.outputURLs = outputURLs
        calculateHashResponse = try await RQESService.calculateHashes(
            rqes,
            documents: documents.map(\.fileURL),
            outputURLs: outputURLs,
            certificates: certs,
            hashAlgorithmOID: self.hashAlgorithmOID!
        )
        
        // STEP 10: Set up an credential authorization request using OAuth2AuthorizeRequest with required parameters
        guard let hashes = calculateHashResponse?.hashes else {
            throw NSError(
                domain: "Signing alogorithm error",
                code: 0,
                userInfo: [NSLocalizedDescriptionKey: "Failes to retrieve hashes"]
            )
        }
        
        authorizationDetails = AuthorizationDetails([
            AuthorizationDetailsItem(
                documentDigests: try hashes.enumerated().map { i,h in
                    try DocumentDigest.forToken(label: documents[i].id, hash: h)
                },
                credentialID: credentialInfo.credentialID,
                hashAlgorithmOID: self.hashAlgorithmOID!,
                locations: [],
                type: "credential"
            )
        ])
        
        guard let details = JSONUtils.stringify(
            authorizationDetails
        ) else {
            throw NSError(
                domain: "Signing alogorithm error",
                code: 0,
                userInfo: [NSLocalizedDescriptionKey: "Failed to create authorization details"]
            )
        }
        
        let credentialResponse = try await rqes.prepareCredentialAuthorizationRequest(
            walletState: state,
            authorizationDetails: details
        )

        return URL(string: credentialResponse.authorizationCodeURL)!
    }
    
    /// Authorizes a credential using the provided authorization code.
    /// - Parameter authorizationCode: A `String` containing the authorization code required for credential authorization.
    /// - Returns: An instance of `RQESServiceCredentialAuthorized` upon successful authorization.
    /// Once the authorizationCode is obtained using the credential authorization URL, it can be used to authorize the credential. The authorized credential can be used to sign the documents.
    public func authorizeCredential(authorizationCode: String) async throws -> RQESServiceCredentialAuthorized {
        
        let authorizationDetailsItems = try self.authorizationDetails?.compactMap { item in
            try item.copy(digestFormat: DigestFormat.base64)
        }
        
        let authorizationDetails: AuthorizationDetails = .init(authorizationDetailsItems!)
        
        // STEP 11: Request OAuth2 token for credential authorization
        let tokenCredentialRequest = AccessTokenRequest(
            code: authorizationCode,
            state: state,
            authorizationDetails: JSONUtils.stringify(authorizationDetails)
        )
        let tokenCredentialResponse = try await rqes.requestAccessTokenAuthFlow(request: tokenCredentialRequest)
        
        let credentialAccessToken = tokenCredentialResponse.accessToken
        return RQESServiceCredentialAuthorized(
            rqes: rqes,
            clientConfig: clientConfig,
            credentialInfo: credentialInfo!,
            credentialAccessToken: credentialAccessToken,
            documents: documents!,
            calculateHashResponse: calculateHashResponse!,
            hashAlgorithmOID: hashAlgorithmOID!,
            defaultSigningAlgorithmOID: defaultSigningAlgorithmOID,
            fileExtension: fileExtension,
            outputURLs: outputURLs!
        )
    }
}
