package emu.lunarcore.server.packet.recv;

import emu.lunarcore.proto.RefreshTriggerByClientCsReqOuterClass.RefreshTriggerByClientCsReq;
import emu.lunarcore.server.game.GameSession;
import emu.lunarcore.server.packet.CmdId;
import emu.lunarcore.server.packet.Opcodes;
import emu.lunarcore.server.packet.PacketHandler;
import emu.lunarcore.server.packet.send.PacketRefreshTriggerByClientScRsp;
import it.unimi.dsi.fastutil.ints.IntOpenHashSet;
import it.unimi.dsi.fastutil.ints.IntSet;

@Opcodes(CmdId.RefreshTriggerByClientCsReq)
public class HandlerRefreshTriggerByClientCsReq extends PacketHandler {

    @Override
    public void handle(GameSession session, byte[] data) throws Exception {
        var req = RefreshTriggerByClientCsReq.parseFrom(data);
        
        IntSet hitTargetList = new IntOpenHashSet();
        for (var targetId: req.getTriggerTargetIdList()) {
            hitTargetList.add(targetId.intValue());
        }
        
        if (session.getPlayer().getScene() != null) {
            session.getPlayer().getScene().handleSummonUnitTriggers(
                    req.getTriggerEntityId(),
                    req.getTriggerName(),
                    req.getTriggerMotion(),
                    hitTargetList
            );
        }
        
        session.send(new PacketRefreshTriggerByClientScRsp(req));
    }

}