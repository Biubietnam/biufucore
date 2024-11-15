package emu.lunarcore.server.game;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

import emu.lunarcore.LunarCore;
import emu.lunarcore.config.ConfigData.GameServerConfig;
import emu.lunarcore.game.battle.BattleService;
import emu.lunarcore.game.drops.DropService;
import emu.lunarcore.game.gacha.GachaService;
import emu.lunarcore.game.inventory.InventoryService;
import emu.lunarcore.game.player.Player;
import emu.lunarcore.game.shop.ShopService;
import emu.lunarcore.server.packet.send.PacketPlayerKickOutScNotify;
import it.unimi.dsi.fastutil.ints.Int2ObjectMap;
import it.unimi.dsi.fastutil.ints.Int2ObjectOpenHashMap;
import kcp.highway.ChannelConfig;
import kcp.highway.KcpServer;
import lombok.Getter;

public class GameServer extends KcpServer {
    private final InetSocketAddress address;
    private final GameServerConfig serverConfig;
    private final RegionInfo info;
    
    private final Int2ObjectMap<Player> players;
    private final Timer gameLoopTimer;
    private long lastTickTime;
    
    // Managers
    @Getter private final GameServerPacketHandler packetHandler;
    @Getter private final GameServerPacketCache packetCache;
    
    @Getter private final BattleService battleService;
    @Getter private final DropService dropService;
    @Getter private final InventoryService inventoryService;
    @Getter private final GachaService gachaService;
    @Getter private final ShopService shopService;

    public GameServer(GameServerConfig serverConfig) {
        // Game Server base
        this.serverConfig = serverConfig;
        this.info = new RegionInfo(this);
        this.address = new InetSocketAddress(serverConfig.getBindAddress(), serverConfig.getBindPort());
        this.players = new Int2ObjectOpenHashMap<>();

        // Setup managers
        this.packetHandler = new GameServerPacketHandler();
        this.packetCache = new GameServerPacketCache();
        
        this.battleService = new BattleService(this);
        this.dropService = new DropService(this);
        this.inventoryService = new InventoryService(this);
        this.gachaService = new GachaService(this);
        this.shopService = new ShopService(this);
        
        // Game loop
        this.lastTickTime = System.currentTimeMillis();
        this.gameLoopTimer = new Timer();
        this.gameLoopTimer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                onTick();
            }
        }, 0, 1000);
    }

    public GameServerConfig getServerConfig() {
        return this.serverConfig;
    }

    public int getPlayerCount() {
        synchronized (this.players) {
            return this.players.size();
        }
    }

    public void registerPlayer(Player player) {
        synchronized (this.players) {
            this.players.put(player.getUid(), player);
        }
    }
    
    public void deregisterPlayer(Player player) {
        synchronized (this.players) {
            Player check = this.players.get(player.getUid());
            if (check == player) {
                this.players.remove(player.getUid());
            }
        }
    }
    
    public List<Integer> getAllPlayerUIDs() {
        synchronized (this.players) {
            return new ArrayList<>(this.players.keySet());
        }
    }
    
    public Player getPlayerByUid(int uid, boolean allowOffline) {
        Player target = null;
        
        // Get player if online
        synchronized (this.players) {
            target = this.players.get(uid);
        }
        
        // Player is not online, but we arent requesting an online one
        if (target == null && allowOffline) {
            target = LunarCore.getGameDatabase().getObjectByUid(Player.class, uid);
        }
        
        return target;
    }

    public Player getOnlinePlayerByUid(int uid) {
        return this.getPlayerByUid(uid, false);
    }
    
    public Player getOnlinePlayerByAccountId(String accountUid) {
        synchronized (this.players) {
            return this.players.values()
                    .stream()
                    .filter(p -> accountUid.equals(p.getAccountUid()))
                    .findFirst()
                    .orElse(null);
        }
    }
    
    public List<Player> getRandomOnlinePlayers(int amount, Player filter) {
        List<Player> list = new ArrayList<>();
        
        synchronized (this.players) {
            var iterator = this.players.values().iterator();
            
            while (iterator.hasNext() && list.size() < amount) {
                Player player = iterator.next();
                
                if (player != filter) {
                    list.add(player);
                }
            }
        }
        
        return list;
    }
    
    public boolean deletePlayer(String accountUid) {
        // Check if player exists
        Player player = this.getOnlinePlayerByAccountId(accountUid);

        // Try to get player from database
        if (player == null) {
            player = LunarCore.getGameDatabase().getObjectByField(Player.class, "accountUid", accountUid);
            if (player == null) return false;
        }
        
        // Delete the player
        player.delete();
        return true;
    }

    public void start() {
        // Setup config and init server
        ChannelConfig channelConfig = new ChannelConfig();
        channelConfig.nodelay(true, getServerConfig().getKcpInterval(), 2, true);
        channelConfig.setMtu(1400);
        channelConfig.setSndwnd(256);
        channelConfig.setRcvwnd(256);
        channelConfig.setTimeoutMillis(getServerConfig().getKcpTimeout() * 1000);
        channelConfig.setUseConvChannel(true);
        channelConfig.setAckNoDelay(true);

        this.init(new GameServerKcpListener(this), channelConfig, address);

        // Setup region info
        this.info.setUp(true);
        this.info.save();
        LunarCore.getHttpServer().forceRegionListRefresh();
        
        // Force a system gc after everything is loaded and started
        System.gc();

        // Done
        LunarCore.getLogger().info("Game Server started on " + address.getPort());
    }
    
    private void onTick() {
        long timestamp = System.currentTimeMillis();
        long delta = timestamp - lastTickTime;
        this.lastTickTime = timestamp;
        
        synchronized (this.players) {
            for (Player player : this.players.values()) {
                try {
                    player.onTick(timestamp, delta);
                } catch (Exception e) {
                    LunarCore.getLogger().error("[UID: " + player.getUid() + "] Player tick error: ", e);
                }
            }
        }
    }

    public void onShutdown() {
        // Kick all players
        List<Integer> playerUIDs = this.getAllPlayerUIDs();
        for (Integer uid : playerUIDs) {
            Player player = this.getOnlinePlayerByUid(uid);
            if (player!= null) {
                player.sendPacket(new PacketPlayerKickOutScNotify(3));
            }
        }

        // Set region info
        this.info.setUp(false);
        this.info.save();
        
        // Save all players
        List<Player> list = new ArrayList<>(players.size());
        list.addAll(players.values());

        // Close server socket
        this.stop();
    }
}
