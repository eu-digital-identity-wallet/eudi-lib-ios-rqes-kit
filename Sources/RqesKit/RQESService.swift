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

public typealias CSCClientConfig = RQES_LIBRARY.CSCClientConfig
public typealias RSSPMetadata = RQES_LIBRARY.InfoServiceResponse
public typealias CredentialInfo = CSCCredentialsListResponse.CredentialInfo
public typealias HashAlgorithmOID = RQES_LIBRARY.HashAlgorithmOID

 // ---------------------------
public class RQESService: RQESServiceProtocol, @unchecked Sendable {
   
	var clientConfig: CSCClientConfig
	var state: String?
	var rqes: RQES!
	var defaultHashAlgorithmOID: HashAlgorithmOID
	var defaultSigningAlgorithmOID: SigningAlgorithmOID?
	var fileExtension: String

	/// Initialize the RQES service
	/// - Parameter clientConfig: CSC client configuration
	/// - Parameter defaultHashAlgorithmOID: The default hash algorithm OID
	/// - Parameter fileExtension: The file extension to be used for the signed documents
	required public init(clientConfig: CSCClientConfig, defaultHashAlgorithmOID: HashAlgorithmOID = .SHA256, fileExtension: String = ".pdf") {
		self.clientConfig = clientConfig
		self.defaultHashAlgorithmOID = defaultHashAlgorithmOID
		self.fileExtension = fileExtension
	}
	
	/// Retrieve the RSSP metadata
	public func getRSSPMetadata() async throws -> RSSPMetadata {
		// STEP 1: Initialize an instance of RQES to access library services
		// This initializes the RQES object for invoking various service methods
		rqes = await RQES(cscClientConfig: clientConfig)
		// STEP 2: Retrieve service information using the InfoService
		let request = InfoServiceRequest(lang: "en-US")
		let response = try await rqes.getInfo(request: request)
		if let algo = response.signAlgorithms.algos.first { defaultSigningAlgorithmOID = SigningAlgorithmOID(rawValue: algo) }
		return response
	}
	
	/// Retrieve the service authorization URL
	/// - Returns: The service authorization URL
	/// The service authorization URL is used to authorize the service to access the user's credentials.
	public func getServiceAuthorizationUrl() async throws -> URL {
		state = UUID().uuidString
		// STEP 5: Set up an authorization request using OAuth2AuthorizeRequest with required parameters
		let response = try await rqes.prepareServiceAuthorizationRequest(walletState: state!)
		return URL(string: response.authorizationCodeURL)!
	}
	
	/// Authorize the service
	/// - Parameter authorizationCode: The authorization code
	/// - Returns: The authorized service instance
	/// Once the authorizationCode is obtained using the service authorization URL, it can be used to authorize the service.
	public func authorizeService(authorizationCode: String) async throws -> RQESServiceAuthorized {
		// STEP 6: Request an OAuth2 Token using the authorization code
		let tokenRequest = OAuth2TokenDto(code: authorizationCode, state: state!)
        let tokenResponse = try await rqes.getOAuth2Token(request: tokenRequest)
		let accessToken = tokenResponse.accessToken
		return RQESServiceAuthorized(rqes, clientConfig: self.clientConfig, defaultHashAlgorithmOID: defaultHashAlgorithmOID, defaultSigningAlgorithmOID: defaultSigningAlgorithmOID, fileExtension: fileExtension, state: state!, accessToken: accessToken)
	}
	
	
	// MARK: - Utils
	static func calculateHashes(_ rqes: RQES, documents: [URL], certificates: [String], accessToken: String, hashAlgorithmOID: HashAlgorithmOID, signatureFormat: SignatureFormat = SignatureFormat.P, conformanceLevel: ConformanceLevel = ConformanceLevel.ADES_B_B, signedEnvelopeProperty: SignedEnvelopeProperty = SignedEnvelopeProperty.ENVELOPED) async throws -> CalculateHashResponse {
		  let request = CalculateHashRequest(
			documents: documents.map { CalculateHashRequest.Document(document: (try! Data(contentsOf: $0)).base64EncodedString(), signatureFormat: signatureFormat, conformanceLevel: conformanceLevel,  signedEnvelopeProperty: SignedEnvelopeProperty.ENVELOPED, container: "No") }, endEntityCertificate: certificates[0], certificateChain: Array(certificates.dropFirst()), hashAlgorithmOID: hashAlgorithmOID)
		  return try await rqes.calculateHash(request: request, accessToken: accessToken)
	  }

	static func saveToTempFile(data: Data, fileExtension: String = ".pdf") throws -> URL {
		let tempDir = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
		let tempFile = tempDir.appendingPathComponent("\(UUID().uuidString)\(fileExtension)")
		try data.write(to: tempFile)
		return tempFile
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
