package emu.lunarcore.command.commands;

import java.util.LinkedList;
import java.util.List;

import emu.lunarcore.command.Command;
import emu.lunarcore.command.CommandArgs;
import emu.lunarcore.command.CommandHandler;
import emu.lunarcore.game.enums.ItemMainType;
import emu.lunarcore.game.inventory.GameItem;

@Command(label = "clear", permission = {"support"}, requireTargetOnline = true, desc = "/clear {relics | lightcones | materials | items} lv(filter level). Removes filter items from the targeted player's inventory.")
public class ClearCommand implements CommandHandler {

    @Override
    public void execute(CommandArgs args) {
        List<GameItem> toRemove = new LinkedList<>();
        String type = args.get(0).toLowerCase();
        
        int filterLevel = Math.max(args.getLevel(), 1);
        
        switch (type) {
            case "relics", "r" -> {
                for (GameItem item : args.getOnlineTarget().getInventory().getItems().values()) {
                    if (item.getItemMainType() == ItemMainType.Relic && item.getLevel() <= filterLevel && !item.isLocked() && !item.isEquipped()) {
                        toRemove.add(item);
                    }
                }
            }
            case "equipment", "lightcones", "lc" -> {
                for (GameItem item : args.getOnlineTarget().getInventory().getItems().values()) {
                    if (item.getItemMainType() == ItemMainType.Equipment && item.getLevel() <= filterLevel && !item.isLocked() && !item.isEquipped()) {
                        toRemove.add(item);
                    }
                }
            }
            case "materials", "mats", "m" -> {
                for (GameItem item : args.getOnlineTarget().getInventory().getItems().values()) {
                    if (item.getItemMainType() == ItemMainType.Material) {
                        toRemove.add(item);
                    }
                }
            }
            case "items", "all" -> {
                for (GameItem item : args.getOnlineTarget().getInventory().getItems().values()) {
                    if (!item.isLocked() && !item.isEquipped()) {
                        toRemove.add(item);
                    }
                }
            }
            case "pets", "pet", "p" -> {
                for (GameItem item : args.getOnlineTarget().getInventory().getItems().values()) {
                    if (item.getItemMainType() == ItemMainType.Pet) {
                        toRemove.add(item);
                    }
                }
            }
        }
        
        args.getOnlineTarget().getInventory().removeItems(toRemove);
        args.sendMessage("Removed " + toRemove.size() + " items");
    }

}
