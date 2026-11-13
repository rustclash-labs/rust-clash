plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "io.github.rustclashlabs.rustclash"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.github.rustclashlabs.rustclash"
        minSdk = 26
        targetSdk = 35
        versionCode = 12
        versionName = "0.3.6"
    }

    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "x86_64")
            isUniversalApk = true
        }
    }

    lint {
        abortOnError = true
        checkReleaseBuilds = false
        disable += setOf(
            "QueryAllPackagesPermission",
            "AppLinkUrlError",
            "GradleDependency",
            "AndroidGradlePluginVersion",
            "NewerVersionAvailable",
        )
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            // Production & GitHub Release builds use a persistent keystore supplied via ANDROID_KEYSTORE_*
            // environment variables so APK v2/v3 signatures remain identical across versions for in-place upgrades.
            val ksPath = System.getenv("ANDROID_KEYSTORE_PATH")
            if (!ksPath.isNullOrBlank()) {
                val resolvedKs = rootProject.file(ksPath)
                if (!resolvedKs.isFile) {
                    throw GradleException("ANDROID_KEYSTORE_PATH points to missing file: ${resolvedKs.absolutePath}")
                }
                val ksPass = System.getenv("ANDROID_KEYSTORE_PASSWORD").orEmpty()
                val aliasName = System.getenv("ANDROID_KEY_ALIAS").orEmpty()
                val aliasPass = System.getenv("ANDROID_KEY_PASSWORD").orEmpty().ifEmpty { ksPass }
                if (ksPass.isBlank() || aliasName.isBlank()) {
                    throw GradleException(
                        "ANDROID_KEYSTORE_PASSWORD and ANDROID_KEY_ALIAS must be non-empty when ANDROID_KEYSTORE_PATH is set"
                    )
                }
                signingConfigs.create("envRelease") {
                    storeFile = resolvedKs
                    storePassword = ksPass
                    keyAlias = aliasName
                    keyPassword = aliasPass
                    enableV1Signing = true
                    enableV2Signing = true
                    enableV3Signing = true
                }.also {
                    signingConfig = it
                }
            }
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
        unitTests.isIncludeAndroidResources = true
        unitTests.all { testTask ->
            val localDeps = File("/tmp/robolectric-deps")
            if (localDeps.isDirectory) {
                testTask.systemProperty("robolectric.offline", "true")
                testTask.systemProperty("robolectric.dependency.dir", localDeps.absolutePath)
            }
        }
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.10.01")
    implementation(composeBom)
    debugImplementation(composeBom)
    testImplementation(composeBom)

    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.activity:activity-ktx:1.9.3")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("com.google.zxing:core:3.5.3")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
    testImplementation("com.google.zxing:core:3.5.3")
    testImplementation("org.robolectric:robolectric:4.14.1")
    testImplementation("androidx.compose.ui:ui-test-junit4")
}
