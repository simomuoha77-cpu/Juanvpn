plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }

android {
    namespace = "com.juanvpn.app"
    compileSdk = 35
    defaultConfig {
        applicationId = "com.juanvpn.app"
        minSdk = 23
        targetSdk = 35
        versionCode = 26
        versionName = "2.9.7"
    }
    signingConfigs {
        getByName("debug") {
            storeFile = file("debug.keystore")
            storePassword = "android"
            keyAlias = "androiddebugkey"
            keyPassword = "android"
        }
        // Real release key, kept OUTSIDE the repository: set these environment variables in the build (for example
        // GitHub Actions secrets). Without them the build falls back to the debug key exactly as before.
        // NOTE: changing the signing key means phones that already have the app must uninstall it first.
        System.getenv("JUAN_KEYSTORE")?.let { path ->
            create("release") {
                storeFile = file(path)
                storePassword = System.getenv("JUAN_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("JUAN_KEY_ALIAS")
                keyPassword = System.getenv("JUAN_KEY_PASSWORD")
            }
        }
    }
    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            isShrinkResources = true
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
        getByName("debug") { isMinifyEnabled = false }
    }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
    // Resolve the duplicate multi-release JAR metadata reported by Android packaging.
    packaging {
        // Hysteria and DNSTT are programs shipped as lib*.so. They must be unpacked so they can be started.
        jniLibs {
            useLegacyPackaging = true
            keepDebugSymbols += setOf("**/libhysteria.so", "**/libdnstt.so")
        }
        resources {
            excludes += "META-INF/versions/*/OSGI-INF/MANIFEST.MF"
            excludes += "META-INF/MANIFEST.MF"
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("com.github.mwiede:jsch:0.2.21")
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
}
