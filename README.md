# Authenticated Encryption
This library combines the .NET built-in AES and HMAC algorithms to provide an easy-to-use interface for doing authenticated encryption.

The library is based on this Gist by James Tuley: https://gist.github.com/jbtule/4336842, but modified slightly to only support the key based versions. Also it does not use the GCM version currently, so there are no external dependencies.