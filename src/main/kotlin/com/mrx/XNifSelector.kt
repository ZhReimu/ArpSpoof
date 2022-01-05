@file:Suppress("UNUSED")

package com.mrx

import org.pcap4j.core.PcapNetworkInterface
import org.pcap4j.core.Pcaps
import java.io.IOException

/**
 * 调试用类, 自动选中某个网卡
 * @property allDevs List<PcapNetworkInterface>
 */
class XNifSelector {

    private companion object {
        val LINE_SEPARATOR: String = System.getProperty("line.separator")
    }

    private val allDevs: List<PcapNetworkInterface> = Pcaps.findAllDevs()

    init {
        if (allDevs.isEmpty()) {
            throw IOException("No NIF to capture.")
        }
    }

    fun selectNetworkInterface(id: Int = 3) = allDevs[id]

    fun showNifList() {
        val sb = StringBuilder(200)
        for ((nifIdx, nif) in allDevs.withIndex()) {
            sb.append("NIF[").append(nifIdx).append("]: ").append(nif.name).append(LINE_SEPARATOR)
            if (nif.description != null) {
                sb.append("      : description: ").append(nif.description).append(LINE_SEPARATOR)
            }
            for (address in nif.linkLayerAddresses) {
                sb.append("      : link layer address: ").append(address).append(LINE_SEPARATOR)
            }
            for (address in nif.addresses) {
                sb.append("      : address: ").append(address.address).append(LINE_SEPARATOR)
            }
        }
        sb.append(LINE_SEPARATOR)
        println(sb.toString())
    }
}