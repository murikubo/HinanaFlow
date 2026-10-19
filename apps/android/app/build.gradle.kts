import java.io.File

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}
android {
    namespace = "dev.hinana.flow"
    compileSdk = 36
    defaultConfig {
        applicationId = "dev.hinana.flow"
        minSdk = 33 // Explicit Wi-Fi-scoped NSD and hardware-key inspection baseline.
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0-alpha1"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    buildFeatures { compose = true }
    sourceSets {
        getByName("test").java.srcDir("src/testShared/java")
        getByName("androidTest").java.srcDir("src/testShared/java")
        getByName("test").resources.srcDir(rootProject.file("../../protocol"))
        getByName("androidTest").assets.srcDir(rootProject.file("../../protocol"))
    }
    signingConfigs.getByName("debug") {storeFile = rootProject.file("../../.build/android-signing/debug.keystore")}
    testOptions { unitTests.isReturnDefaultValues = false }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}
dependencies {
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation(platform("androidx.compose:compose-bom:2025.04.01"))
    implementation("androidx.compose.material3:material3")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
}

// A standard DEBUG APK signing key only, inside ignored project output.
// This is separate from the non-exportable Android Keystore LAN identity.
val localDebugKey = rootProject.file("../../.build/android-signing/debug.keystore")
val prepareLocalDebugKey = tasks.register<Exec>("prepareLocalDebugKey") {
    onlyIf { !localDebugKey.exists() }
    doFirst { localDebugKey.parentFile.mkdirs() }
    commandLine(File(System.getProperty("java.home"), "bin/keytool").absolutePath,
        "-genkeypair", "-keystore", localDebugKey.absolutePath, "-storepass", "android", "-keypass", "android",
        "-alias", "androiddebugkey", "-dname", "CN=Android Debug,O=Android,C=US", "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000")
}
tasks.matching { it.name.startsWith("validateSigningDebug") }.configureEach { dependsOn(prepareLocalDebugKey) }
