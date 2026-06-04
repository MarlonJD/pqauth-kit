plugins {
    kotlin("jvm") version "2.3.21"
}

group = "io.github.marlonjd.pqauthkit"
version = "0.1.0-SNAPSHOT"

kotlin {
    jvmToolchain(21)
}

dependencies {
    implementation("org.bouncycastle:bcprov-jdk18on:1.84")
    testImplementation(kotlin("test"))
    testImplementation("junit:junit:4.13.2")
}

tasks.test {
    useJUnit()
}
