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
import Foundation
import MdocDataModel18013
import RQESLib

/// Captures a signing attempt and stores one transaction per document.
struct RQESSigningLog {
    let logger: (any TransactionLogger)?
    let certificateIdentifier: String?
    let serviceName: MultiLangString?
    let documents: [Document]
    let hashes: [String]
    let outputURLs: [URL]
    private let identifier = UUID().uuidString

    func record(result: TransactionResult, reason: String? = nil) async {
        guard let logger else { return }
        let time = Date()
        for (index, document) in documents.enumerated() {
            let digest = hashes.indices.contains(index)
                ? try? DocumentDigests(digests: [hashes[index]], output: .base64).hashes.first
                : nil
            let size = outputURLs.indices.contains(index)
                ? try? outputURLs[index].resourceValues(forKeys: [.fileSizeKey]).fileSize
                : nil
            let entry = TransactionEntry.signingSealing(.init(
                transactionIdentifier: "\(identifier):\(index)",
                time: time,
                transactionResult: result,
                reasonOfNoncompletion: reason,
                signingTransactionIdentifier: identifier,
                certificateIdentifier: certificateIdentifier,
                dtbsr: digest,
                fileIdentifier: document.id,
                fileName: document.fileURL.lastPathComponent,
                fileSize: size.flatMap { $0 > 0 ? String($0) : nil },
                interactingPartyName: serviceName
            ))
            // A storage failure must not replace the signing result or skip other documents.
            try? await logger.log(transaction: entry)
        }
    }
}
