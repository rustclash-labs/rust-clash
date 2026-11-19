# Preserve runtime annotations and generic signatures under R8 release minification
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod

# Preserve JNI entrypoints and VpnService.protectSocket callback invoked from Rust libproxy_ffi.so
-keep class io.github.rustclashlabs.rustclash.vpn.NativeBridge { *; }
-keep class io.github.rustclashlabs.rustclash.vpn.RustClashVpnService {
    public boolean protectSocket(int);
}
-keep class io.github.rustclashlabs.rustclash.security.AndroidKeystoreVault {
    public byte[] wrapMasterKey(byte[]);
    public byte[] unwrapMasterKey(byte[]);
}
-dontwarn com.google.zxing.**
