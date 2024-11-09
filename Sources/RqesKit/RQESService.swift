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

public typealias RSSPMetadata = RQES_LIBRARY.InfoServiceResponse
public typealias CredentialInfo = CSCCredentialsListResponse.CredentialInfo
public typealias HashAlgorithmOID = RQES_LIBRARY.HashAlgorithmOID

 // ---------------------------
public class RQESService: RQESServiceProtocol, @unchecked Sendable {
   
	var baseProviderUrl: String?
	var clientConfig: CSCClientConfig
	var codeChallenge: String?
	var verifier: String?
	var state: String?
	var rqes: RQES!
	
	/// Initialize the RQES service
	/// - Parameter clientConfig: CSC client configuration
	required public init(clientConfig: CSCClientConfig) {
		self.clientConfig = clientConfig
	}
	
	/// Retrieve the RSSP metadata
	public func getRSSPMetadata() async throws -> RSSPMetadata {
		// STEP 1: Initialize an instance of RQES to access library services
		// This initializes the RQES object for invoking various service methods
		rqes = await RQES()
		// STEP 2: Retrieve service information using the InfoService
		let request = InfoServiceRequest(lang: "en-US")
		let response = try await rqes.getInfo(request: request)
		baseProviderUrl = response.oauth2
		return response
	}
	
	/// Retrieve the service authorization URL
	/// - Parameter cookie: Cookie
	/// - Returns: The service authorization URL
	/// The service authorization URL is used to authorize the service to access the user's credentials.
	public func getServiceAuthorizationUrl(cookie: String? = nil) async throws -> URL {
		if baseProviderUrl == nil { baseProviderUrl = try await getRSSPMetadata().oauth2 }
		let urlString = "\(baseProviderUrl!)/oauth2/authorize"
		guard let url = URL(string: urlString) else { throw ClientError.invalidRequestURL }
		verifier = Self.createCodeVerifier()
		codeChallenge = Self.codeChallenge(for: verifier!)
		state = UUID().uuidString
		let authorizeRequest = OAuth2AuthorizeRequest(responseType: "code", clientId: clientConfig.clientId, redirectUri: clientConfig.redirectUri, scope: RQES_LIBRARY.Scope.SERVICE, codeChallenge: codeChallenge!, codeChallengeMethod: "S256", state: state!, cookie: cookie ?? "")
		let queryItems = authorizeRequest.toQueryItems()
		var components = URLComponents(url: url, resolvingAgainstBaseURL: false)
		components?.queryItems = queryItems
		guard let completeUrl = components?.url else { throw OAuth2AuthorizeError.invalidAuthorizationDetails 	}
		return completeUrl
	}
	
	/// Authorize the service
	/// - Parameter authorizationCode: The authorization code
	/// - Returns: The authorized service instance
	/// Once the authorizationCode is obtained using the service authorization URL, it can be used to authorize the service.
	public func authorizeService(authorizationCode: String) async throws -> RQESServiceAuthorized {
		// STEP 6: Request an OAuth2 Token using the authorization code
		let tokenRequest = OAuth2TokenRequest(clientId: clientConfig.clientId, redirectUri: clientConfig.redirectUri, grantType: "authorization_code", codeVerifier: verifier!, code: authorizationCode, state: state!, auth: nil)
		let tokenResponse = try await rqes.getOAuth2Token(request: tokenRequest)
		let accessToken = tokenResponse.accessToken
		return RQESServiceAuthorized(rqes, clientConfig: self.clientConfig, accessToken: accessToken, baseProviderUrl: baseProviderUrl!)
	}
	
	
	// MARK: - Utils
	static func calculateHashes(_ rqes: RQES, documents: [Data], certificates: [String], accessToken: String, signatureFormat: SignatureFormat = SignatureFormat.P, conformanceLevel: ConformanceLevel = ConformanceLevel.ADES_B_B, signedEnvelopeProperty: SignedEnvelopeProperty = SignedEnvelopeProperty.ENVELOPED) async throws -> CalculateHashResponse {
		  let request = CalculateHashRequest(
			documents: documents.map { CalculateHashRequest.Document(document: $0.base64EncodedString(), signatureFormat: signatureFormat, conformanceLevel: conformanceLevel,  signedEnvelopeProperty: SignedEnvelopeProperty.ENVELOPED, container: "No") }, endEntityCertificate: certificates[0], certificateChain: Array(certificates.dropFirst()), hashAlgorithmOID: HashAlgorithmOID.SHA256)
		  return try await rqes.calculateHash(request: request, accessToken: accessToken)
	  }
	
	static func createCodeVerifier() -> String {
		var buffer = [UInt8](repeating: 0, count: 32)
		_ = SecRandomCopyBytes(kSecRandomDefault, buffer.count, &buffer)
		return Data(buffer).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "").trimmingCharacters(in: .whitespaces)
	}
	
	static func codeChallenge(for verifier: String) -> String {
		guard let data = verifier.data(using: .utf8) else { fatalError() }
		let hash = data.hash(for: .sha256)
		return hash.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "").trimmingCharacters(in: .whitespaces)
	}
	
}

extension Data {
	enum Algorithm {
		case sha256
		
		var digestLength: Int {
			switch self {
			case .sha256: return Int(CC_SHA256_DIGEST_LENGTH)
			}
		}
	}
	
	func hash(for algorithm: Algorithm) -> Data {
		let hashBytes = UnsafeMutablePointer<UInt8>.allocate(capacity: algorithm.digestLength)
		defer { hashBytes.deallocate() }
		switch algorithm {
		case .sha256:
			withUnsafeBytes { (buffer) -> Void in
				CC_SHA256(buffer.baseAddress!, CC_LONG(buffer.count), hashBytes)
			}
		}
		
		return Data(bytes: hashBytes, count: algorithm.digestLength)
	}
}

extension X509.Certificate {
	var base64String: String {
		var ser = DER.Serializer()
		try! serialize(into: &ser)
		return Data(ser.serializedBytes).base64EncodedString()
	}
}
