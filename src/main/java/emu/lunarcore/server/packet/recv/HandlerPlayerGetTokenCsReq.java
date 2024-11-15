package emu.lunarcore.server.packet.recv;

import emu.lunarcore.LunarCore;
import emu.lunarcore.config.ConfigManager;
import emu.lunarcore.game.account.Account;
import emu.lunarcore.game.player.Player;
import emu.lunarcore.proto.PlayerGetTokenCsReqOuterClass.PlayerGetTokenCsReq;
import emu.lunarcore.server.game.GameSession;
import emu.lunarcore.server.packet.CmdId;
import emu.lunarcore.server.packet.Opcodes;
import emu.lunarcore.server.packet.PacketHandler;
import emu.lunarcore.server.packet.SessionState;
import emu.lunarcore.server.packet.send.PacketPlayerGetTokenScRsp;
import emu.lunarcore.server.packet.send.PacketPlayerKickOutScNotify;

@Opcodes(CmdId.PlayerGetTokenCsReq)
public class HandlerPlayerGetTokenCsReq extends PacketHandler {

    @Override
    public void handle(GameSession session, byte[] data) throws Exception {
        // Parse packet data
        var req = PlayerGetTokenCsReq.parseFrom(data);

        // Authenticate
        Account account = LunarCore.getAccountDatabase().getObjectByField(Account.class, "_id", req.getAccountUid());
        if (account == null || !account.getComboToken().equals(req.getToken())) {
            return;
        }

        // Set account object for session
        session.setAccount(account);

        // Check if account is banned
        if (session.getAccount().isBanned()) {
            session.send(new PacketPlayerKickOutScNotify(4));
        }

        // If playerCount reach the set maxPlayers, newly logged-in players will be kicked out
        int maxPlayers = ConfigManager.getConfig().getAccountOptions().maxPlayers;
        int playerCount = LunarCore.getGameServer().getPlayerCount();
        if (maxPlayers > -1 &&  playerCount >= maxPlayers) {
            session.getPlayer().sendPacket(new PacketPlayerKickOutScNotify(5));
            return;
        }

        // Get player from database, if it doesnt exist, we create it
        Player player = LunarCore.getGameDatabase().getObjectByField(Player.class, "accountUid", account.getUid());

        if (player == null) {
            player = new Player(session);
            LunarCore.getGameDatabase().save(player);
        }
        
        // Dont let people log on to the same player at the same time
        Player prevPlayer = session.getServer().getOnlinePlayerByUid(player.getUid());
        if (prevPlayer != null) {
            prevPlayer.sendPacket(new PacketPlayerKickOutScNotify(0));
        }

        // Set player object for session
        session.setPlayer(player);

        // Load player data from database
        player.onLogin();

        // Set session state
        session.setUseSecretKey(true);
        session.setState(SessionState.WAITING_FOR_LOGIN);

        // Finish and send packet
        session.send(new PacketPlayerGetTokenScRsp(session));
    }

}
