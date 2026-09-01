# Official plugin bridge

This package owns the signed plugin manifest, permissions and release lifecycle. Once it is installed and enabled, XSEC Desktop loads its frontend in an opaque iframe and grants only the manifest-declared Host RPC methods.

The browser workspace tool receives a private, capability-bound surface bridge: the host validates the project/session/page at open time, associates one native Chrome surface with one iframe, and forwards JPEG frames on that iframe's private data stream. Surface input, frame acknowledgements, close, and Desktop-level focus presentation must match that handle. The package frontend is the workspace renderer.

The manifest also owns the browser settings page and its `pluginData` RPC grants, so installing the package restores both the workspace browser and its custom Chrome-path setting.
