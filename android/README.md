# Android app (deferred)

This directory is reserved for the Android app that wraps the `core`
library via JNI.

The app will be a native Kotlin app; the `core` C++ library is
statically linked into a JNI bridge. The Kotlin layer is the UI; the
C++ core does all the cryptographic work.

For now: empty.
