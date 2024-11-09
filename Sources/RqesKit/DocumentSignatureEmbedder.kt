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

import eu.europa.ec.eudi.rqes.Signature
import java.security.cert.X509Certificate

/**
 * Embeds a signature into a document.
 */
fun interface DocumentSignatureEmbedder {
    /**
     * Embeds a signature into a document.
     * @param document the document to embed the signature into
     * @param signature the signature to embed
     * @param certificates the certificates to use when embedding the signature (optional)
     * @return the document with the embedded signature
     */
    fun embedSignature(
        document: Document,
        signature: Signature,
        certificates: List<X509Certificate>?
    ): Document
}