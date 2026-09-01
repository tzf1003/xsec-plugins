# Official plugin bridge

This package owns the signed plugin manifest, permissions and release lifecycle. When it is installed and enabled, XSEC Desktop loads its declared frontend in an opaque sandbox. The package owns the project-file UI and interaction state; Desktop exposes only the declared, capability-bound workspace read and Composer write RPCs. Package state, rather than the application installer, remains the source of truth.
