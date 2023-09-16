import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.9.0"
    application
}

group = "me.administrator"
version = "1.0-SNAPSHOT"

repositories {
    maven("https://maven.aliyun.com/repository/central")
    mavenCentral()
}

dependencies {
    // https://mvnrepository.com/artifact/org.pcap4j/pcap4j-core
    implementation("org.pcap4j:pcap4j-core:1.8.2")
    // https://mvnrepository.com/artifact/org.pcap4j/pcap4j-packetfactory-static
    implementation("org.pcap4j:pcap4j-packetfactory-static:1.8.2")
    implementation("org.slf4j:slf4j-api:2.0.9")
    implementation("ch.qos.logback:logback-classic:1.4.11")
    implementation("ch.qos.logback:logback-core:1.4.11")

    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}

tasks.withType<KotlinCompile> {
    kotlinOptions.jvmTarget = "11"
}

application {
    mainClass.set("MainKt")
}