# EUDI Remote Qualified Electronic Signature (RQES) Kit library for iOS

:heavy_exclamation_mark: **Important!** Before you proceed, please read
the [EUDI Wallet Reference Implementation project description](https://github.com/eu-digital-identity-wallet/.github/blob/main/profile/reference-implementation.md)

## Overview

This module provides the core functionality for the EUDI Wallet, focusing on the Remote Qualified
Electronic Signature (RQES) service. The `RQESService` interface defines methods for obtaining
credential authorization URLs, authorizing credentials, and signing documents. It ensures secure and
compliant electronic signatures by interacting with authorized credentials and handling document
signing processes.

## Installation
To use RQES Kit, add the following dependency to your Package.swift:
```swift
dependencies: [
    .package(url: "https://github.com/niscy-eudiw/eudi-lib-ios-rqes-kit", branch: "initial")
]
```

Then add the Eudi Wallet package to your target's dependencies:
```swift
dependencies: [
    .product(name: "RqesKit", package: "eudi-lib-ios-rqes-kit"),
]
```

## Document signing flow

```mermaid
sequenceDiagram
    participant Client
    participant RQESService
    participant RQESServiceAuthorized
    participant RQESServiceCredentialAuthorized
    Client ->>+ RQESService: getRSSPMetadata()
    RQESService -->>- Client: RSSPMetadata
    Client ->>+ RQESService: getServiceAuthorizationUrl()
    RQESService -->>- Client: URL
    Client ->>+ RQESService: authorizeService(authorizationCode)
    RQESService -->>- Client: RQESServiceAuthorized
    Client ->>+ RQESServiceAuthorized: getCredentialsList(request)
    RQESServiceAuthorized -->>- Client: List<CredentialInfo>
    Client ->>+ RQESServiceAuthorized: getCredentialAuthorizationUrl(credential, documents)
    RQESServiceAuthorized -->>- Client: URL
    Client ->>+ RQESServiceAuthorized: authorizeCredential(authorizationCode)
    RQESServiceAuthorized -->>- Client: RQESServiceCredentialAuthorized
    Client ->>+ RQESServiceCredentialAuthorized: signDocuments(algorithmOID)
    RQESServiceCredentialAuthorized -->>- Client: SignedDocuments
```

## How to use

At first, construct an instance of the `RQESService` like shown below:

```swift
let cscClientConfig = CSCClientConfig(
        OAuth2Client: CSCClientConfig.OAuth2Client(
                clientId: "wallet-client",
                clientSecret: "somesecret2"
        ),
        authFlowRedirectionURI: "https://oauthdebugger.com/debug",
        scaBaseURL: "https://walletcentric.signer.eudiw.dev"
)
var rqesService = RQESService(
    clientConfig: cscClientConfig,
    defaultHashAlgorithmOID: .SHA256
)
```

You can get the metadata of the RQES service by calling the `getRSSPMetadata` method:

```swift
let metadata = try await rqesService.getRSSPMetadata()
``` 

To authorize the service, you need to get the authorization URL and open it in a browser. After the
user has authorized the service, the browser will be redirected to the `redirectUri`,
that
is configured in the `CSCClientConfig`, with a query parameter named `code` containing the
authorization code. You can then authorize the service by calling the `authorizeService` method:

```swift
let authorizationUrl = try await rqesService.getServiceAuthorizationUrl()

// Open the authorizationUrl in a browser
// After the user has authorized the service, the browser will be redirected to the redirectUri
// with a query parameter named "code" containing the authorization code

let authorizedService = try await rqesService.authorizeService(authorizationCode)
```

With the authorized service, you can list the available credentials by calling the `getCredentialsList`
method.

You can then select the credential you want to use, prepare the documents to sign, and get
the credential authorization URL by calling the `getCredentialAuthorizationUrl` method. After the
user has authorized the credential, you can authorize it by calling the `authorizeCredential`
method.

Finally, you can sign the documents by calling the `signDocuments` method.

```swift
let credentials = try await authorizedService.getCredentialsList()
// Use the credentials to select the one you want to use
// For example, select the first credential

let credential = credentials.first!
// Prepare the documents to sign
let unsignedDocuments = [Document(label: "Document to sign", fileURL: Bundle.main.url(forResource: "document", withExtension:"pdf")))]

// Get the credential authorization URL for the selected credential and documents
let credentialAuthorizationUrl = try await authorizedService.getCredentialAuthorizationUrl(
    credentialInfo: credential,
    documents: unsignedDocuments,
)

// Use the credentialAuthorizationUrl to open a browser and let the user authorize the credential
// and get the authorization code from the redirect URI query parameter

// Authorize the credential
let authorizedCredential = try await authorizedService.authorizeCredential(authorizationCode)

// Sign the documents
let signAlgorithm = SigningAlgorithmOID.ECDSA_SHA256
let signedDocuments = try await authorizedCredential.signDocuments(signAlgorithmOID: signAlgorithm)
```

## How to contribute

We welcome contributions to this project. To ensure that the process is smooth for everyone
involved, follow the guidelines found in [CONTRIBUTING.md](CONTRIBUTING.md).


### License details

Copyright (c) 2023 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.