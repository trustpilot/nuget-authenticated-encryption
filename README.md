# Authenticated Encryption

This library combines the .NET built-in AES and HMAC algorithms to provide an easy-to-use interface for doing authenticated encryption.
The library is based on this Gist by James Tuley: https://gist.github.com/jbtule/4336842, but modified slightly to only support the key based versions. Also it does not use the GCM version currently, so there are no external dependencies.

## Build Status

[![Build status](https://ci.appveyor.com/api/projects/status/du8bm82f1ru6ja3n?svg=true)](https://ci.appveyor.com/project/TrustpilotAppVeyor/nuget-authenticated-encryption)

## Installation

Install via [NuGet](http://www.nuget.org/packages/AuthenticatedEncryption/):

```
Install-Package AuthenticatedEncryption
```

## More information

The library consists of a single static class. This makes it very easy to use. It uses [Authenticated Encryption with Associated Data (AEAD)](https://en.wikipedia.org/wiki/Authenticated_encryption), using the approach called “Encrypt then MAC” (EtM). It uses one key for the encryption part (cryptkey) and another key for the MAC part (authkey).

This is a simple example of encrypting and decrypting some string:

```c#
const string Input = "this is a test input string";
var cryptKey = AuthenticatedEncryption.NewKey();
var authKey = AuthenticatedEncryption.NewKey();

var cipherText = AuthenticatedEncryption.Encrypt(Input, cryptKey, authKey);
var plainText = AuthenticatedEncryption.Decrypt(cipherText, cryptKey, authKey);
```

## Maintainer(s)

- [Søren Pedersen (@spewu)](https://github.com/spewu)
