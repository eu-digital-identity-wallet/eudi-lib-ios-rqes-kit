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

public class RQESServiceAuthorized: RQESServiceAuthorizedProtocol, @unchecked Sendable {

    var rqes: RQES
    var clientConfig: CSCClientConfig
	var baseProviderUrl: String
    var accessToken: String
	var calculateHashResponse: CalculateHashResponse?
	var codeChallenge: String?
	var documents: [Document]?
	var verifier: String?
	var state: String?
	var credentialInfo: CredentialInfo?
    var authorizationDetailsJsonString: String?
	var hashAlgorithmOID: HashAlgorithmOID?

    public init(_ rqes: RQES, clientConfig: CSCClientConfig, accessToken: String, baseProviderUrl: String) {
		self.rqes = rqes
		self.baseProviderUrl = baseProviderUrl
        self.clientConfig = clientConfig
		self.accessToken = accessToken
    }

    /// Retrieve the list of credentials
    /// - Returns: The list of credentials
    /// The credentials are the user's credentials that can be used to sign the documents.
	public func getCredentialsList() async throws -> [CredentialInfo] {
		// STEP 7: Request the list of credentials using the access token
		let requestDefault = CSCCredentialsListRequest(credentialInfo: true, certificates: "chain", certInfo: true)
		  let response = try await rqes.getCredentialsList(request: requestDefault, accessToken: accessToken)
		guard let credentialInfos = response.credentialInfos else { throw OAuth2TokenError.invalidResponse }
		return credentialInfos
	  }

    /// Get the credential authorization URL
    /// - Parameters:
    ///   - credentialInfo: Information about the credential.
    ///   - documents: An array of documents that will be signed.
    ///   - hashAlgorithmOID: The object identifier (OID) of the hash algorithm to be used, optional.
    ///   - certificates: An optional array of X509 certificates.
    ///   - cookie: An optional cookie string.
    /// - Returns: The credential authorization URL
    /// The credential authorization URL is used to authorize the credential that will be used to sign the documents.
    public func getCredentialAuthorizationUrl(credentialInfo: CredentialInfo, documents: [Document], hashAlgorithmOID: HashAlgorithmOID? = nil, certificates: [X509.Certificate]? = nil, cookie: String? = nil) async throws -> URL {
		self.documents = documents
		self.credentialInfo = credentialInfo
		self.hashAlgorithmOID = hashAlgorithmOID ?? clientConfig.defaultHashAlgorithmOID
		let certs = certificates?.map(\.base64String) ?? credentialInfo.cert.certificates
		let urlString = "\(baseProviderUrl)/oauth2/authorize"
		guard let url = URL(string: urlString) else { throw ClientError.invalidRequestURL }
		// STEP 9: calculate hashes
		calculateHashResponse = try await RQESService.calculateHashes(rqes, documents: documents.map(\.fileURL), certificates: certs, accessToken: accessToken, hashAlgorithmOID: self.hashAlgorithmOID!)
		// STEP 10: Set up an credential authorization request using OAuth2AuthorizeRequest with required parameters
		let authorizationDetails = AuthorizationDetails([
				AuthorizationDetailsItem(documentDigests: calculateHashResponse!.hashes.enumerated().map { i,h in DocumentDigest(label: documents[i].id, hash: h) }, credentialID: credentialInfo.credentialID, hashAlgorithmOID: self.hashAlgorithmOID!, locations: [], type: "credential") ])
		authorizationDetailsJsonString = JSONUtils.stringify(authorizationDetails)
		verifier = RQESService.createCodeVerifier()
		codeChallenge = RQESService.codeChallenge(for: verifier!)
		state = UUID().uuidString
		let authorizeCredentialRequest = OAuth2AuthorizeRequest(responseType: "code", clientId: clientConfig.clientId, redirectUri: clientConfig.redirectUri, scope: Scope.CREDENTIAL, codeChallenge: codeChallenge!, codeChallengeMethod: "S256", state: state!, credentialID: credentialInfo.credentialID, authorizationDetails:authorizationDetailsJsonString!, cookie: cookie ?? "")
		let queryItems = authorizeCredentialRequest.toQueryItems()
		var components = URLComponents(url: url, resolvingAgainstBaseURL: false)
		components?.queryItems = queryItems
		guard let completeUrl = components?.url else { throw OAuth2AuthorizeError.invalidAuthorizationDetails 	}
		return completeUrl
	}

    /// Authorizes a credential using the provided authorization code.
    /// - Parameter authorizationCode: A `String` containing the authorization code required for credential authorization.
    /// - Returns: An instance of `RQESServiceCredentialAuthorized` upon successful authorization.
    /// Once the authorizationCode is obtained using the credential authorization URL, it can be used to authorize the credential. The authorized credential can be used to sign the documents.
	public func authorizeCredential(authorizationCode: String) async throws -> RQESServiceCredentialAuthorized {
		// STEP 11: Request OAuth2 token for credential authorization
		let tokenCredentialRequest = OAuth2TokenRequest(clientId: clientConfig.clientId, redirectUri: clientConfig.redirectUri,
				grantType: "authorization_code", codeVerifier: verifier!, code: authorizationCode, state: state!,
				//auth: OAuth2TokenRequest.BasicAuth(username: password: ),
				authorizationDetails: authorizationDetailsJsonString!)
		let tokenCredentialResponse = try await rqes.getOAuth2Token(request: tokenCredentialRequest)
		let credentialAccessToken = tokenCredentialResponse.accessToken
		return RQESServiceCredentialAuthorized(rqes: rqes, clientConfig: clientConfig, credentialInfo: credentialInfo!, credentialAccessToken: credentialAccessToken, documents: documents!, calculateHashResponse: calculateHashResponse!, hashAlgorithmOID: hashAlgorithmOID!)
	}
}
