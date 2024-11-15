// Code generated by protocol buffer compiler. Do not edit!
package emu.lunarcore.proto;

import java.io.IOException;
import us.hebi.quickbuf.FieldName;
import us.hebi.quickbuf.InvalidProtocolBufferException;
import us.hebi.quickbuf.JsonSink;
import us.hebi.quickbuf.JsonSource;
import us.hebi.quickbuf.MessageFactory;
import us.hebi.quickbuf.ProtoMessage;
import us.hebi.quickbuf.ProtoSink;
import us.hebi.quickbuf.ProtoSource;
import us.hebi.quickbuf.ProtoUtil;
import us.hebi.quickbuf.RepeatedInt;

public final class BattleSkillInfoOuterClass {
  /**
   * Protobuf type {@code BattleSkillInfo}
   */
  public static final class BattleSkillInfo extends ProtoMessage<BattleSkillInfo> implements Cloneable {
    private static final long serialVersionUID = 0L;

    /**
     * <code>optional double NLMOBJCCDEL = 2;</code>
     */
    private double nLMOBJCCDEL;

    /**
     * <code>optional double damage = 4;</code>
     */
    private double damage;

    /**
     * <code>optional uint32 skill_id = 1;</code>
     */
    private int skillId;

    /**
     * <code>repeated uint32 battle_target_list = 3;</code>
     */
    private final RepeatedInt battleTargetList = RepeatedInt.newEmptyInstance();

    private BattleSkillInfo() {
    }

    /**
     * @return a new empty instance of {@code BattleSkillInfo}
     */
    public static BattleSkillInfo newInstance() {
      return new BattleSkillInfo();
    }

    /**
     * <code>optional double NLMOBJCCDEL = 2;</code>
     * @return whether the nLMOBJCCDEL field is set
     */
    public boolean hasNLMOBJCCDEL() {
      return (bitField0_ & 0x00000001) != 0;
    }

    /**
     * <code>optional double NLMOBJCCDEL = 2;</code>
     * @return this
     */
    public BattleSkillInfo clearNLMOBJCCDEL() {
      bitField0_ &= ~0x00000001;
      nLMOBJCCDEL = 0D;
      return this;
    }

    /**
     * <code>optional double NLMOBJCCDEL = 2;</code>
     * @return the nLMOBJCCDEL
     */
    public double getNLMOBJCCDEL() {
      return nLMOBJCCDEL;
    }

    /**
     * <code>optional double NLMOBJCCDEL = 2;</code>
     * @param value the nLMOBJCCDEL to set
     * @return this
     */
    public BattleSkillInfo setNLMOBJCCDEL(final double value) {
      bitField0_ |= 0x00000001;
      nLMOBJCCDEL = value;
      return this;
    }

    /**
     * <code>optional double damage = 4;</code>
     * @return whether the damage field is set
     */
    public boolean hasDamage() {
      return (bitField0_ & 0x00000002) != 0;
    }

    /**
     * <code>optional double damage = 4;</code>
     * @return this
     */
    public BattleSkillInfo clearDamage() {
      bitField0_ &= ~0x00000002;
      damage = 0D;
      return this;
    }

    /**
     * <code>optional double damage = 4;</code>
     * @return the damage
     */
    public double getDamage() {
      return damage;
    }

    /**
     * <code>optional double damage = 4;</code>
     * @param value the damage to set
     * @return this
     */
    public BattleSkillInfo setDamage(final double value) {
      bitField0_ |= 0x00000002;
      damage = value;
      return this;
    }

    /**
     * <code>optional uint32 skill_id = 1;</code>
     * @return whether the skillId field is set
     */
    public boolean hasSkillId() {
      return (bitField0_ & 0x00000004) != 0;
    }

    /**
     * <code>optional uint32 skill_id = 1;</code>
     * @return this
     */
    public BattleSkillInfo clearSkillId() {
      bitField0_ &= ~0x00000004;
      skillId = 0;
      return this;
    }

    /**
     * <code>optional uint32 skill_id = 1;</code>
     * @return the skillId
     */
    public int getSkillId() {
      return skillId;
    }

    /**
     * <code>optional uint32 skill_id = 1;</code>
     * @param value the skillId to set
     * @return this
     */
    public BattleSkillInfo setSkillId(final int value) {
      bitField0_ |= 0x00000004;
      skillId = value;
      return this;
    }

    /**
     * <code>repeated uint32 battle_target_list = 3;</code>
     * @return whether the battleTargetList field is set
     */
    public boolean hasBattleTargetList() {
      return (bitField0_ & 0x00000008) != 0;
    }

    /**
     * <code>repeated uint32 battle_target_list = 3;</code>
     * @return this
     */
    public BattleSkillInfo clearBattleTargetList() {
      bitField0_ &= ~0x00000008;
      battleTargetList.clear();
      return this;
    }

    /**
     * <code>repeated uint32 battle_target_list = 3;</code>
     *
     * This method returns the internal storage object without modifying any has state.
     * The returned object should not be modified and be treated as read-only.
     *
     * Use {@link #getMutableBattleTargetList()} if you want to modify it.
     *
     * @return internal storage object for reading
     */
    public RepeatedInt getBattleTargetList() {
      return battleTargetList;
    }

    /**
     * <code>repeated uint32 battle_target_list = 3;</code>
     *
     * This method returns the internal storage object and sets the corresponding
     * has state. The returned object will become part of this message and its
     * contents may be modified as long as the has state is not cleared.
     *
     * @return internal storage object for modifications
     */
    public RepeatedInt getMutableBattleTargetList() {
      bitField0_ |= 0x00000008;
      return battleTargetList;
    }

    /**
     * <code>repeated uint32 battle_target_list = 3;</code>
     * @param value the battleTargetList to add
     * @return this
     */
    public BattleSkillInfo addBattleTargetList(final int value) {
      bitField0_ |= 0x00000008;
      battleTargetList.add(value);
      return this;
    }

    /**
     * <code>repeated uint32 battle_target_list = 3;</code>
     * @param values the battleTargetList to add
     * @return this
     */
    public BattleSkillInfo addAllBattleTargetList(final int... values) {
      bitField0_ |= 0x00000008;
      battleTargetList.addAll(values);
      return this;
    }

    @Override
    public BattleSkillInfo copyFrom(final BattleSkillInfo other) {
      cachedSize = other.cachedSize;
      if ((bitField0_ | other.bitField0_) != 0) {
        bitField0_ = other.bitField0_;
        nLMOBJCCDEL = other.nLMOBJCCDEL;
        damage = other.damage;
        skillId = other.skillId;
        battleTargetList.copyFrom(other.battleTargetList);
      }
      return this;
    }

    @Override
    public BattleSkillInfo mergeFrom(final BattleSkillInfo other) {
      if (other.isEmpty()) {
        return this;
      }
      cachedSize = -1;
      if (other.hasNLMOBJCCDEL()) {
        setNLMOBJCCDEL(other.nLMOBJCCDEL);
      }
      if (other.hasDamage()) {
        setDamage(other.damage);
      }
      if (other.hasSkillId()) {
        setSkillId(other.skillId);
      }
      if (other.hasBattleTargetList()) {
        getMutableBattleTargetList().addAll(other.battleTargetList);
      }
      return this;
    }

    @Override
    public BattleSkillInfo clear() {
      if (isEmpty()) {
        return this;
      }
      cachedSize = -1;
      bitField0_ = 0;
      nLMOBJCCDEL = 0D;
      damage = 0D;
      skillId = 0;
      battleTargetList.clear();
      return this;
    }

    @Override
    public BattleSkillInfo clearQuick() {
      if (isEmpty()) {
        return this;
      }
      cachedSize = -1;
      bitField0_ = 0;
      battleTargetList.clear();
      return this;
    }

    @Override
    public boolean equals(Object o) {
      if (o == this) {
        return true;
      }
      if (!(o instanceof BattleSkillInfo)) {
        return false;
      }
      BattleSkillInfo other = (BattleSkillInfo) o;
      return bitField0_ == other.bitField0_
        && (!hasNLMOBJCCDEL() || ProtoUtil.isEqual(nLMOBJCCDEL, other.nLMOBJCCDEL))
        && (!hasDamage() || ProtoUtil.isEqual(damage, other.damage))
        && (!hasSkillId() || skillId == other.skillId)
        && (!hasBattleTargetList() || battleTargetList.equals(other.battleTargetList));
    }

    @Override
    public void writeTo(final ProtoSink output) throws IOException {
      if ((bitField0_ & 0x00000001) != 0) {
        output.writeRawByte((byte) 17);
        output.writeDoubleNoTag(nLMOBJCCDEL);
      }
      if ((bitField0_ & 0x00000002) != 0) {
        output.writeRawByte((byte) 33);
        output.writeDoubleNoTag(damage);
      }
      if ((bitField0_ & 0x00000004) != 0) {
        output.writeRawByte((byte) 8);
        output.writeUInt32NoTag(skillId);
      }
      if ((bitField0_ & 0x00000008) != 0) {
        for (int i = 0; i < battleTargetList.length(); i++) {
          output.writeRawByte((byte) 24);
          output.writeUInt32NoTag(battleTargetList.array()[i]);
        }
      }
    }

    @Override
    protected int computeSerializedSize() {
      int size = 0;
      if ((bitField0_ & 0x00000001) != 0) {
        size += 9;
      }
      if ((bitField0_ & 0x00000002) != 0) {
        size += 9;
      }
      if ((bitField0_ & 0x00000004) != 0) {
        size += 1 + ProtoSink.computeUInt32SizeNoTag(skillId);
      }
      if ((bitField0_ & 0x00000008) != 0) {
        size += (1 * battleTargetList.length()) + ProtoSink.computeRepeatedUInt32SizeNoTag(battleTargetList);
      }
      return size;
    }

    @Override
    @SuppressWarnings("fallthrough")
    public BattleSkillInfo mergeFrom(final ProtoSource input) throws IOException {
      // Enabled Fall-Through Optimization (QuickBuffers)
      int tag = input.readTag();
      while (true) {
        switch (tag) {
          case 17: {
            // nLMOBJCCDEL
            nLMOBJCCDEL = input.readDouble();
            bitField0_ |= 0x00000001;
            tag = input.readTag();
            if (tag != 33) {
              break;
            }
          }
          case 33: {
            // damage
            damage = input.readDouble();
            bitField0_ |= 0x00000002;
            tag = input.readTag();
            if (tag != 8) {
              break;
            }
          }
          case 8: {
            // skillId
            skillId = input.readUInt32();
            bitField0_ |= 0x00000004;
            tag = input.readTag();
            if (tag != 26) {
              break;
            }
          }
          case 26: {
            // battleTargetList [packed=true]
            input.readPackedUInt32(battleTargetList, tag);
            bitField0_ |= 0x00000008;
            tag = input.readTag();
            if (tag != 0) {
              break;
            }
          }
          case 0: {
            return this;
          }
          default: {
            if (!input.skipField(tag)) {
              return this;
            }
            tag = input.readTag();
            break;
          }
          case 24: {
            // battleTargetList [packed=false]
            tag = input.readRepeatedUInt32(battleTargetList, tag);
            bitField0_ |= 0x00000008;
            break;
          }
        }
      }
    }

    @Override
    public void writeTo(final JsonSink output) throws IOException {
      output.beginObject();
      if ((bitField0_ & 0x00000001) != 0) {
        output.writeDouble(FieldNames.nLMOBJCCDEL, nLMOBJCCDEL);
      }
      if ((bitField0_ & 0x00000002) != 0) {
        output.writeDouble(FieldNames.damage, damage);
      }
      if ((bitField0_ & 0x00000004) != 0) {
        output.writeUInt32(FieldNames.skillId, skillId);
      }
      if ((bitField0_ & 0x00000008) != 0) {
        output.writeRepeatedUInt32(FieldNames.battleTargetList, battleTargetList);
      }
      output.endObject();
    }

    @Override
    public BattleSkillInfo mergeFrom(final JsonSource input) throws IOException {
      if (!input.beginObject()) {
        return this;
      }
      while (!input.isAtEnd()) {
        switch (input.readFieldHash()) {
          case -1342189469: {
            if (input.isAtField(FieldNames.nLMOBJCCDEL)) {
              if (!input.trySkipNullValue()) {
                nLMOBJCCDEL = input.readDouble();
                bitField0_ |= 0x00000001;
              }
            } else {
              input.skipUnknownField();
            }
            break;
          }
          case -1339126929: {
            if (input.isAtField(FieldNames.damage)) {
              if (!input.trySkipNullValue()) {
                damage = input.readDouble();
                bitField0_ |= 0x00000002;
              }
            } else {
              input.skipUnknownField();
            }
            break;
          }
          case 2147320652:
          case 2142452169: {
            if (input.isAtField(FieldNames.skillId)) {
              if (!input.trySkipNullValue()) {
                skillId = input.readUInt32();
                bitField0_ |= 0x00000004;
              }
            } else {
              input.skipUnknownField();
            }
            break;
          }
          case 1658064039:
          case 2141562245: {
            if (input.isAtField(FieldNames.battleTargetList)) {
              if (!input.trySkipNullValue()) {
                input.readRepeatedUInt32(battleTargetList);
                bitField0_ |= 0x00000008;
              }
            } else {
              input.skipUnknownField();
            }
            break;
          }
          default: {
            input.skipUnknownField();
            break;
          }
        }
      }
      input.endObject();
      return this;
    }

    @Override
    public BattleSkillInfo clone() {
      return new BattleSkillInfo().copyFrom(this);
    }

    @Override
    public boolean isEmpty() {
      return ((bitField0_) == 0);
    }

    public static BattleSkillInfo parseFrom(final byte[] data) throws
        InvalidProtocolBufferException {
      return ProtoMessage.mergeFrom(new BattleSkillInfo(), data).checkInitialized();
    }

    public static BattleSkillInfo parseFrom(final ProtoSource input) throws IOException {
      return ProtoMessage.mergeFrom(new BattleSkillInfo(), input).checkInitialized();
    }

    public static BattleSkillInfo parseFrom(final JsonSource input) throws IOException {
      return ProtoMessage.mergeFrom(new BattleSkillInfo(), input).checkInitialized();
    }

    /**
     * @return factory for creating BattleSkillInfo messages
     */
    public static MessageFactory<BattleSkillInfo> getFactory() {
      return BattleSkillInfoFactory.INSTANCE;
    }

    private enum BattleSkillInfoFactory implements MessageFactory<BattleSkillInfo> {
      INSTANCE;

      @Override
      public BattleSkillInfo create() {
        return BattleSkillInfo.newInstance();
      }
    }

    /**
     * Contains name constants used for serializing JSON
     */
    static class FieldNames {
      static final FieldName nLMOBJCCDEL = FieldName.forField("NLMOBJCCDEL");

      static final FieldName damage = FieldName.forField("damage");

      static final FieldName skillId = FieldName.forField("skillId", "skill_id");

      static final FieldName battleTargetList = FieldName.forField("battleTargetList", "battle_target_list");
    }
  }
}
