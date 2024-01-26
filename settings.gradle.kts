rootProject.name = "ArpSpoof"

pluginManagement {
    repositories {
        maven { url = uri("https://maven.aliyun.com/repository/public/") }
        maven { url = uri("https://maven.aliyun.com/repositories/jcenter") }
        maven { url = uri("https://maven.aliyun.com/repositories/google") }
        maven { url = uri("https://maven.aliyun.com/repositories/central") }
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        maven { url = uri("https://maven.aliyun.com/repository/public/") }
        maven { url = uri("https://maven.aliyun.com/repositories/jcenter") }
        maven { url = uri("https://maven.aliyun.com/repositories/google") }
        maven { url = uri("https://maven.aliyun.com/repositories/central") }
        google()
        mavenCentral()
    }
}