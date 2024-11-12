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

/// The RQES service protocol
public protocol RQESServiceProtocol {
	associatedtype RQESServiceAuthorizedImpl: RQESServiceAuthorizedProtocol
	/// Initialize the RQES service
	/// - Parameter clientConfig: CSC client configuration
	init(clientConfig: CSCClientConfig, defaultHashAlgorithmOID: HashAlgorithmOID, defaultSigningAlgorithmOID: SigningAlgorithmOID)
	/// Retrieve the RSSP metadata
	func getRSSPMetadata() async throws -> RSSPMetadata
	/// Retrieve the service authorization URL
	/// - Parameter cookie: Cookie
	/// - Returns: The service authorization URL
	/// The service authorization URL is used to authorize the service to access the user's credentials.
	func getServiceAuthorizationUrl(cookie: String?) async throws -> URL
	/// Authorize the service
	/// - Parameter authorizationCode: The authorization code
	/// - Returns: The authorized service instance
	/// Once the authorizationCode is obtained using the service authorization URL, it can be used to authorize the service.
	func authorizeService(authorizationCode: String) async throws -> RQESServiceAuthorizedImpl
}

/// The authorized service protocol.
/// The authorized service is used to access the user's credentials
public protocol RQESServiceAuthorizedProtocol {
	associatedtype RQESServiceCredentialAuthorizedImpl: RQESServiceCredentialAuthorizedProtocol
	/// Retrieve the list of credentials
	/// - Returns: The list of credentials
	/// The credentials are the user's credentials that can be used to sign the documents.
	func getCredentialsList() async throws -> [CredentialInfo]
	/// Get the credential authorization URL
	/// - Parameters:
	///   - credentialInfo: Information about the credential.
	///   - documents: An array of documents that will be signed.
	///   - hashAlgorithmOID: The object identifier (OID) of the hash algorithm to be used, optinal.
	///   - certificates: An optional array of X509 certificates.
	///   - cookie: An optional cookie string.
	/// - Returns: The credential authorization URL
	/// The credential authorization URL is used to authorize the credential that will be used to sign the documents.
	func getCredentialAuthorizationUrl(credentialInfo: CredentialInfo, documents: [Document], hashAlgorithmOID: HashAlgorithmOID?, certificates: [X509.Certificate]?, cookie: String?) async throws -> URL
	/// Authorizes a credential using the provided authorization code.
	/// - Parameter authorizationCode: A `String` containing the authorization code required for credential authorization.
	/// - Returns: An instance of `RQESServiceCredentialAuthorizedImpl` upon successful authorization.
	/// Once the authorizationCode is obtained using the credential authorization URL, it can be used to authorize the credential. The authorized credential can be used to sign the documents.
	func authorizeCredential(authorizationCode: String) async throws -> RQESServiceCredentialAuthorizedImpl
}

/// The credential authorized protocol.

/// The authorized credential is used to sign the documents. The list of documents that will be signed using the authorized credential are the documents
/// that were passed to the ``RQESServiceAuthorizedProtocol.getCredentialAuthorizationUrl`` method.
public protocol RQESServiceCredentialAuthorizedProtocol {
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
	func signDocuments(signAlgorithmOID: SigningAlgorithmOID?, certificates: [X509.Certificate]?) async throws -> [Document]
}