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

public final class VerifyHandler implements Handler {
    @Override
    public void handle(@NotNull Context ctx) throws Exception {
        RemoteReqJson req = JsonUtils.decode(ctx.body(), RemoteReqJson.class);

        int uid = req.uid;
        int reqCode = req.code;
        String key = req.key;
        String ipAddress = Utils.getClientIpAddress(ctx);

        // Check req formats
        if (uid == 0) {
            ctx.json(new RemoteRspJson(403, "The player UID was not entered."));
            return;
        }
        if (reqCode == 0) {
            ctx.json(new RemoteRspJson(403, "The verification code was not entered."));
            return;
        }
        if (key.isEmpty()) {
            ctx.json(new RemoteRspJson(403, "The remote password was not entered."));
            return;
        }

        // Check if player is online
        Player sender = LunarCore.getGameServer().getOnlinePlayerByUid(uid);
        if (sender == null) {
            ctx.json(new RemoteRspJson(404, "The player is not found or is not online."));
            return;
        }

        // Check if account set code before
        int setCode = ApplyHandler.getCodeByUid(uid);
        if (setCode == 0) {
            ctx.json(new RemoteRspJson(500, "The player has not set a code yet."));
            return;
        }

        // Check if code is correct
        if (reqCode != setCode) {
            ctx.json(new RemoteRspJson(500, "The verification code is incorrect."));
            return;
        }

        // Save password
        PasswordManager.saveOrUpdatePassword(uid, key);

        // Logs
        LunarCore.getLogger().info(ipAddress + " set a key for " + uid);
        sender.sendMessage(ipAddress + " set a key for you, your remote pwd is: " + key);

        // Response
        ctx.json(new RemoteRspJson());
    }
}