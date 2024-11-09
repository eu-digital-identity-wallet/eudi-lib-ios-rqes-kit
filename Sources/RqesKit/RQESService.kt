/*
 * Copyright (c) 2024 European Commission
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

package eu.europa.ec.eudi.rqes.core

import eu.europa.ec.eudi.rqes.AlgorithmOID
import eu.europa.ec.eudi.rqes.AuthorizationCode
import eu.europa.ec.eudi.rqes.CredentialInfo
import eu.europa.ec.eudi.rqes.CredentialsListRequest
import eu.europa.ec.eudi.rqes.HashAlgorithmOID
import eu.europa.ec.eudi.rqes.HttpsUrl
import eu.europa.ec.eudi.rqes.RSSPMetadata
import java.security.cert.X509Certificate

/**
 * The RQES service interface.
 * This interface provides the methods to interact with the RQES service.
 * The service is divided into two parts:
 * - The first part is the authorization part, which is used to authorize the service to access the user's credentials.
 * - The second part is the credential part, which is used to sign the documents.
 *
 * HTTP client factory should be used. This property is optional can be used to provide a custom
 * Ktor HTTP client factory, that can be used to create the HTTP client.
 */
interface RQESService {
    /**
     * Get the RSSP metadata.
     * This method is used to get the RSSP metadata.
     * The RSSP metadata contains the information about the RSSP.
     * @see [RSSPMetadata]
     *
     * @return The RSSP metadata as a [Result] of [RSSPMetadata].
     */
    suspend fun getRSSPMetadata(): Result<RSSPMetadata>

    /**
     * Get the service authorization URL.
     * This method is used to get the service authorization URL.
     * The service authorization URL is used to authorize the service to access the user's credentials.
     *
     * @return The service authorization URL as a [Result] of [HttpsUrl].
     */
    suspend fun getServiceAuthorizationUrl(): Result<HttpsUrl>

    /**
     * Authorize with the service.
     * This method is used to authorize the service to access the user's credentials.
     * Once the authorizationCode is obtained using the service authorization URL, it can be used to authorize the service.
     *
     * @param authorizationCode The authorization code.
     * @return The authorized service as a [Result] of [Authorized]. [Authorized] is the interface
     * to interact with the authorized service.
     */
    suspend fun authorizeService(authorizationCode: AuthorizationCode): Result<Authorized>


    /**
     * The authorized service interface.
     * This interface provides the methods to interact with the authorized service.
     * The authorized service is used to access the user's credentials and sign the documents.
     */
    interface Authorized {

        /**
         * List the credentials.
         * This method is used to list the credentials.
         * The credentials are the user's credentials that can be used to sign the documents.
         *
         * Method accepts [CredentialsListRequest] as a parameter to filter the credentials.
         * If the request is null, all the valid credentials should be returned.
         *
         * @param request The credentials list request.
         * @return The list of credentials as a [Result] of [List] of [CredentialInfo].
         */
        suspend fun listCredentials(request: CredentialsListRequest? = null): Result<List<CredentialInfo>>

        /**
         * Get the credential authorization URL.
         * This method is used to get the credential authorization URL.
         *
         * The credential authorization URL is used to authorize the credential that will be used
         * to sign the documents.
         *
         * @param credential The credential info.
         * @param documents The list of documents to be signed.
         * @param hashAlgorithmOID The hash algorithm OID.
         * Implementations should use the default hash algorithm if this parameter is null.
         * @param certificates The list of certificates.
         * Implementations should use the default certificates if this parameter is null.
         * @return The credential authorization URL as a [Result] of [HttpsUrl].
         */
        suspend fun getCredentialAuthorizationUrl(
            credential: CredentialInfo,
            documents: List<Document>,
            hashAlgorithmOID: HashAlgorithmOID? = null,
            certificates: List<X509Certificate>? = null,
        ): Result<HttpsUrl>

        /**
         * Authorize the credential.
         * This method is used to authorize the credential that will be used to sign the documents.
         * Once the authorizationCode is obtained using the credential authorization URL, it can be used to authorize the credential.
         * The authorized credential can be used to sign the documents.
         * @param authorizationCode The authorization code.
         * @return The authorized credential as a [Result] of [CredentialAuthorized].
         */
        suspend fun authorizeCredential(authorizationCode: AuthorizationCode): Result<CredentialAuthorized>

    }

    /**
     * The credential authorized interface.
     * This interface provides the methods to interact with the authorized credential.
     * The authorized credential is used to sign the documents.
     *
     * The list of documents that will be signed using the authorized credential are the documents
     * that were passed to the [RQESService.Authorized.getCredentialAuthorizationUrl] method.
     */
    interface CredentialAuthorized {

        /**
         * Sign the documents.
         * This method is used to sign the documents.
         * The documents are the list of documents that were passed to the [RQESService.Authorized.getCredentialAuthorizationUrl] method.
         * The documents are signed using the authorized credential.
         * @param algorithmOID The algorithm OID. Implementations should use the default algorithm if this parameter is null.
         * @param certificates The list of certificates. Implementations should use the default certificates if this parameter is null.
         * @return The list of signed documents as a [Result] of [List] of [Document]. The signed documents are the documents that were signed.
         */
        suspend fun signDocuments(
            algorithmOID: AlgorithmOID? = null,
            certificates: List<X509Certificate>? = null
        ): Result<List<Document>>
    }
}