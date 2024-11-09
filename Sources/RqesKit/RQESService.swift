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

public final class RQESService: @unchecked Sendable {

    func testInvokeInfoService() async throws {

        // STEP 1: Initialize an instance of RQES to access library services
        // This initializes the RQES object for invoking various service methods
        let rqes = await RQES()

        // STEP 2: Retrieve service information using the InfoService
        let request = InfoServiceRequest(lang: "en-US")
        let response = try await rqes.getInfo(request: request)

        // STEP 3: Create a login request with test credentials
        let loginRequest = LoginRequest(
            username: "8PfCAQzTmON+FHDvH4GW/g+JUtg5eVTgtqMKZFdB/+c=;FirstName;TesterUser",
            password: "5adUg@35Lk_Wrm3")

        // STEP 4: Perform the login operation and capture the response
        let loginResponse = try await rqes.login(request: loginRequest)

        // STEP 5: Set up an authorization request using OAuth2AuthorizeRequest with required parameters
        let authorizeRequest = OAuth2AuthorizeRequest(
            responseType: "code",
            clientId: "wallet-client",
            redirectUri: "https://walletcentric.signer.eudiw.dev/tester/oauth/login/code",
            scope: "service",
            codeChallenge: "V4n5D1_bu7BPMXWsTulFVkC4ASFmeS7lHXSqIf-vUwI",
            codeChallengeMethod: "S256",
            state: "erv8utb5uie",
            credentialID: nil,
            signatureQualifier: nil,
            numSignatures: nil,
            hashes: nil,
            hashAlgorithmOID: nil,
            authorizationDetails: nil,
            requestUri: nil,
            cookie: loginResponse.cookie!
        )

        let authorizeResponse = try await rqes.getAuthorizeUrl(request: authorizeRequest)

        // STEP 6: Request an OAuth2 Token using the authorization code
        let tokenRequest = OAuth2TokenRequest(
            clientId: "wallet-client-tester",
            redirectUri: "https://walletcentric.signer.eudiw.dev/tester/oauth/login/code",
            grantType: "authorization_code",
            codeVerifier: "z34oHaauNSc13ScLRDmbQrJ5bIR9IDzRCWZTRRAPtlV",
            code: authorizeResponse.code,
            state: "erv8utb5uie",
            auth: OAuth2TokenRequest.BasicAuth(
                username: "wallet-client",
                password: "somesecret2"
            )
        )

        let tokenResponse = try await rqes.getOAuth2Token(request: tokenRequest)

        // STEP 7: Request the list of credentials using the access token
        let credentialListRequest = CSCCredentialsListRequest(
            credentialInfo: true,
            certificates: "chain",
            certInfo: true
        )

        let credentialListResponse = try await rqes.getCredentialsList(
            request: credentialListRequest, accessToken: tokenResponse.accessToken)

        // STEP 8: Request the list of credentials using the access token
        let credentialInfoRequest = CSCCredentialsInfoRequest(
            credentialID: credentialListResponse.credentialIDs[0],
            credentialInfo: true,
            certificates: "chain",
            certInfo: true
        )

        let credentialInfoResponse = try await rqes.getCredentialsInfo(
            request: credentialInfoRequest, accessToken: tokenResponse.accessToken)

        // This loads the PDF document from the specified file name within the resources,
        // encodes it in Base64 format, and assigns it to the pdfDocument variable for further processing.
        let pdfDocument = FileUtils.getBase64EncodedDocument(fileNameWithExtension: "sample 1.pdf")

        // STEP 9: Request the list of credentials using the access token
        let calculateHashRequest = CalculateHashRequest(
            documents: [
                CalculateHashRequest.Document(
                    document: pdfDocument!,
                    signatureFormat: "P",
                    conformanceLevel: "Ades-B-B",
                    signedEnvelopeProperty: "ENVELOPED",
                    container: "No"
                )
            ],
            endEntityCertificate: (credentialInfoResponse.cert?.certificates?[0])!,
            certificateChain: [(credentialInfoResponse.cert?.certificates?[1])!],
            hashAlgorithmOID: "2.16.840.1.101.3.4.2.1"
        )

        let calculateHashResponse = try await rqes.calculateHash(
            request: calculateHashRequest, accessToken: tokenResponse.accessToken)

        // STEP 10: Set up an credential authorization request using OAuth2AuthorizeRequest with required parameters
        let authorizationDetails = AuthorizationDetails([
            AuthorizationDetailsItem(
                documentDigests: [
                    DocumentDigest(
                        label: "A sample pdf",
                        hash: calculateHashResponse.hashes[0]
                    )
                ],
                credentialID: credentialListResponse.credentialIDs[0],
                hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
                locations: [],
                type: "credential"
            )
        ])

        let authDetailsJson = String(
            data: try JSONEncoder().encode(authorizationDetails), encoding: .utf8)!

        let authorizeCredentialRequest = OAuth2AuthorizeRequest(
            responseType: "code",
            clientId: "wallet-client",
            redirectUri: "https://walletcentric.signer.eudiw.dev/tester/oauth/login/code",
            scope: "credential",
            codeChallenge: "V4n5D1_bu7BPMXWsTulFVkC4ASFmeS7lHXSqIf-vUwI",
            codeChallengeMethod: "S256",
            state: "erv8utb5uie",
            credentialID: credentialListResponse.credentialIDs[0],
            signatureQualifier: nil,
            numSignatures: nil,
            hashes: nil,
            hashAlgorithmOID: nil,
            authorizationDetails: authDetailsJson,
            requestUri: nil,
            cookie: loginResponse.cookie!
        )

        let authorizeCredentialResponse = try await rqes.getAuthorizeUrl(
            request: authorizeCredentialRequest)

        // STEP 11: Request OAuth2 token for credential authorization
        let tokenCredentialRequest = OAuth2TokenRequest(
            clientId: "wallet-client-tester",
            redirectUri: "https://walletcentric.signer.eudiw.dev/tester/oauth/login/code",
            grantType: "authorization_code",
            codeVerifier: "z34oHaauNSc13ScLRDmbQrJ5bIR9IDzRCWZTRRAPtlV",
            code: authorizeCredentialResponse.code,
            state: "erv8utb5uie",
            auth: OAuth2TokenRequest.BasicAuth(
                username: "wallet-client",
                password: "somesecret2"
            ),
            authorizationDetails: authDetailsJson
        )

        let tokenCredentialResponse = try await rqes.getOAuth2Token(request: tokenCredentialRequest)

        // STEP 12: Sign the calculated hash with the credential
        let signHashRequest = SignHashRequest(
            credentialID: credentialListResponse.credentialIDs[0],
            hashes: [calculateHashResponse.hashes[0]],
            hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
            signAlgo: "1.2.840.113549.1.1.1",
            operationMode: "S"
        )

        let signHashResponse = try await rqes.signHash(
            request: signHashRequest, accessToken: tokenCredentialResponse.accessToken)

        // STEP 13: Obtain the signed document
        let obtainSignedDocRequest = ObtainSignedDocRequest(
            documents: [
              ObtainSignedDocRequest.Document(
                    document: pdfDocument!, signatureFormat: "P", conformanceLevel: "Ades-B-B",
                    signedEnvelopeProperty: "ENVELOPED", container: "No")
                    
            ],
            endEntityCertificate: credentialInfoResponse.cert?.certificates?.first ?? "",
            certificateChain: credentialInfoResponse.cert?.certificates?.dropFirst().map { $0 }
                ?? [],
            hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
            date: calculateHashResponse.signatureDate,
            signatures: signHashResponse.signatures ?? []
        )

        let obtainSignedDocResponse = try await rqes.obtainSignedDoc(
            request: obtainSignedDocRequest, accessToken: tokenCredentialResponse.accessToken)
        let base64String = obtainSignedDocResponse.documentWithSignature[0]

        // Save the decoded data to the user's documents folder
         _ = FileUtils.decodeAndSaveBase64Document(base64String: base64String, fileNameWithExtension: "signed.pdf")
    }
}
