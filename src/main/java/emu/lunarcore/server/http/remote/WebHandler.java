package emu.lunarcore.server.http.remote;

import emu.lunarcore.LunarCore;
import io.javalin.http.Handler;

import com.sun.management.OperatingSystemMXBean;
import java.lang.management.ManagementFactory;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;
import java.util.Timer;
import java.util.TimerTask;

public class WebHandler {

    private static Integer cpuUsagePercentage = null;
    private static String appStartTime;
    private static int startCpuUsage;
    private static final Queue<Map<String, Object>> cpuUsageHistory = new LinkedList<>();
    private static final int MAX_HISTORY_SIZE = 5;
    private static final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("dd/MM/yy HH:mm");

    // Method to initialize start time and CPU usage at startup
    public static void initializeStartInfo() {
        appStartTime = LocalDateTime.now().format(dateTimeFormatter);
        startCpuUsage = getCpuUsage();
        addCpuUsageEntry(appStartTime, startCpuUsage);
        scheduleHourlyCpuCollection();
    }

    // Function to get the current CPU usage percentage
    public static int getCpuUsage() {
        try {
            if (cpuUsagePercentage == null) {
                OperatingSystemMXBean osBean = (OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
                double cpuLoad = osBean.getCpuLoad() * 100;
                cpuUsagePercentage = (int) Math.round(cpuLoad);
            }
            return cpuUsagePercentage;
        } catch (Exception e) {
            e.printStackTrace();
            return -1;
        }
    }

    // Handler for current CPU usage endpoint
    public static final Handler cpuHandler = ctx -> {
        try {
            int cpuUsage = getCpuUsage();
            ctx.json(Map.of("cpupercent", cpuUsage));
            LunarCore.getLogger().info("Client requested CPU usage: " + cpuUsage + "%");
            resetCpuUsage();
        } catch (Exception e) {
            ctx.status(500).result("Unable to fetch CPU usage");
        }
    };

    // Handler for CPU usage history endpoint
    public static final Handler cpuHistoryHandler = ctx -> {
        try {
            ctx.json(Map.of("cpuUsageHistory", cpuUsageHistory));
            LunarCore.getLogger().info("Client requested CPU usage history: " + cpuUsageHistory);
        } catch (Exception e) {
            ctx.status(500).result("Unable to fetch CPU usage history");
        }
    };

    // Reset method for CPU usage percentage
    public static void resetCpuUsage() {
        cpuUsagePercentage = null;
    }

    // Method to add a new CPU usage entry to the history
    private static void addCpuUsageEntry(String time, int cpuUsage) {
        if (cpuUsageHistory.size() >= MAX_HISTORY_SIZE) {
            cpuUsageHistory.poll();  // Remove the oldest entry
        }
        cpuUsageHistory.add(Map.of("time", time, "cpupercent", cpuUsage));
    }

    // Schedule hourly CPU collection starting at the next full hour
    private static void scheduleHourlyCpuCollection() {
        Timer timer = new Timer(true);
        LocalDateTime nextHour = LocalDateTime.now().withMinute(0).withSecond(0).plusHours(1);

        long delay = java.time.Duration.between(LocalDateTime.now(), nextHour).toMillis();
        long period = 60 * 60 * 1000;  // 1 hour in milliseconds

        timer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                String currentTime = LocalDateTime.now().format(dateTimeFormatter);
                int currentCpuUsage = getCpuUsage();
                addCpuUsageEntry(currentTime, currentCpuUsage);
                LunarCore.getLogger().info("Hourly CPU usage recorded: " + currentCpuUsage + "% at " + currentTime);
                resetCpuUsage();
            }
        }, delay, period);
    }
}
