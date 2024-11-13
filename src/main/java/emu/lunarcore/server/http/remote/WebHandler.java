package emu.lunarcore.server.http.remote;

import emu.lunarcore.LunarCore;
import io.javalin.http.Context;
import io.javalin.http.Handler;

import com.sun.management.OperatingSystemMXBean;
import java.lang.management.ManagementFactory;
import java.util.Map;

public class WebHandler {

    // Variable to store the initialized CPU usage percentage
    private static Integer cpuUsagePercentage = null;

    // Function to get the current CPU usage percentage, but initialized only once
    public static int getCpuUsage() {
        try {
            // If the CPU usage has not been initialized, calculate and store it
            if (cpuUsagePercentage == null) {
                OperatingSystemMXBean osBean = (OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
                double cpuLoad = osBean.getCpuLoad() * 100;  // Get system CPU load and convert to percentage
                cpuUsagePercentage = (int) Math.round(cpuLoad);  // Store the percentage
            }

            // Return the stored CPU usage percentage
            return cpuUsagePercentage;

        } catch (Exception e) {
            // Handle any errors that occur during the calculation
            e.printStackTrace();
            return -1;  // Returning -1 to indicate an error
        }
    }

    // Handler for CPU usage endpoint
    public static final Handler cpuHandler = ctx -> {
        try {
            // Get the current CPU usage
            int cpuUsage = getCpuUsage();
            
            // Return the CPU usage in JSON format
            ctx.json(Map.of("cpupercent", cpuUsage));
            LunarCore.getLogger().info("Client requested CPU usage: " + cpuUsage + "%");
            resetCpuUsage();
        } catch (Exception e) {
            // Handle errors and send a response indicating failure
            ctx.status(500).result("Unable to fetch CPU usage");
        }
    };

    // Reset method (optional, if you need to force recalculation)
    public static void resetCpuUsage() {
        cpuUsagePercentage = null;  // Reset the value, forcing recalculation next time
    }
}
