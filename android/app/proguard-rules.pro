# Preserve runtime annotations and generic signatures under R8 release minification
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod

# Preserve JNI entrypoints and VpnService.protectSocket callback invoked from Rust libproxy_ffi.so
-keep class io.github.rustclashlabs.rustclash.vpn.NativeBridge { *; }
-keep class io.github.rustclashlabs.rustclash.vpn.RustClashVpnService {
    public boolean protectSocket(int);
}
-dontwarn com.google.zxing.**
