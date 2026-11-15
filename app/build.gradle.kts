plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }

android {
    namespace = "com.juanvpn.app"
    compileSdk = 35
    defaultConfig {
        applicationId = "com.juanvpn.app"
        minSdk = 23
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.0"
    }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }

    // Android uses the base classes from these multi-release JARs. Exclude
    // Java-version-specific META-INF entries to prevent duplicate OSGi
    // manifest resources from JSch and Bouncy Castle during APK merging.
    packaging {
        resources {
            excludes += "/META-INF/versions/**"
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("com.github.mwiede:jsch:0.2.21")
    // Required by mwiede/JSch for Ed25519 SSH host keys on Android runtimes.
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
}
