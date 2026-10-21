plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.tunlion.coresmoke"
    compileSdk = 35
    defaultConfig {
        applicationId = "com.tunlion.coresmoke"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk { abiFilters += "x86_64" }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    // Use the Android AAR: the plain jar lacks the packaged jnidispatch .so.
    implementation("net.java.dev.jna:jna:5.17.0@aar")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}
