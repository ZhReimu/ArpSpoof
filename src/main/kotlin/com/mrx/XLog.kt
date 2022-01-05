package com.mrx

import org.apache.logging.log4j.Level
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger
import org.apache.logging.log4j.core.config.ConfigurationFactory
import org.apache.logging.log4j.core.config.Configurator

object XLog {

    init {
        val builder = ConfigurationFactory.newConfigurationBuilder()
        val console = builder.newAppender("stdout", "Console")
        val std = builder.newLayout("PatternLayout").apply {
            addAttribute("pattern", "%d{yyyy-MM-dd HH:mm:ss.SSS} [%t] %logger{36} %-5level: %msg%n%throwable")
        }
        console.add(std)
        builder.add(console)
        builder.add(builder.newRootLogger(Level.INFO).apply { add(builder.newAppenderRef("stdout")) })
        Configurator.initialize(builder.build())
    }

    fun getLogger(name: String): Logger = LogManager.getLogger(name)

    fun getLogger(clazz: Class<*>): Logger = LogManager.getLogger(clazz.name)
}