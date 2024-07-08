package emu.lunarcore.server.http.remote;

import emu.lunarcore.LunarCore;
import emu.lunarcore.game.player.Player;
import emu.lunarcore.server.http.objects.RemoteReqJson;
import emu.lunarcore.server.http.objects.RemoteRspJson;
import emu.lunarcore.util.JsonUtils;
import emu.lunarcore.util.Utils;
import io.javalin.http.Context;
import io.javalin.http.Handler;

import org.jetbrains.annotations.NotNull;

public final class RemoteHandler implements Handler {
    @Override
    public void handle(@NotNull Context ctx) throws Exception {
        RemoteReqJson req = JsonUtils.decode(ctx.body(), RemoteReqJson.class);

        int uid = req.uid;
        String reqKey = PasswordManager.hashWithMD5(req.key);
        String cmd = req.cmd;
        String ipAddress = Utils.getClientIpAddress(ctx);

        // Check req formats
        if (uid == 0) {
            ctx.json(new RemoteRspJson(403, "The player UID was not entered."));
            return;
        }
        if (reqKey.isEmpty()) {
            ctx.json(new RemoteRspJson(403, "The player remote password was not entered."));
            return;
        }

        // Check if player is online
        Player sender = LunarCore.getGameServer().getOnlinePlayerByUid(uid);
        if (sender == null) {
            ctx.json(new RemoteRspJson(404, "The player is not found or is not online."));
            return;
        }

        // Check if key is set before
        String setKey = PasswordManager.getPasswordByUid(uid);
        if (setKey == null) {
            ctx.json(new RemoteRspJson(500, "The player remote password is not set."));
            return;
        }

        // Check if key is correct
        if (!reqKey.equals(setKey)) {
            ctx.json(new RemoteRspJson(201, "The player remote password is incorrect."));
            return;
        }

        // Invoke command
        LunarCore.getCommandManager().invoke(sender, cmd, ctx);

        // Logs
        LunarCore.getLogger().info(ipAddress + " invoke '" + cmd + "' to " + uid);
        sender.sendMessage(ipAddress + " invoke '" + cmd + "' to you.");

    }
}