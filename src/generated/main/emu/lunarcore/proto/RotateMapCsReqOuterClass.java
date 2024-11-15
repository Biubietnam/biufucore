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

public final class RotateMapCsReqOuterClass {
  /**
   * Protobuf type {@code RotateMapCsReq}
   */
  public static final class RotateMapCsReq extends ProtoMessage<RotateMapCsReq> implements Cloneable {
    private static final long serialVersionUID = 0L;

    /**
     * <code>optional uint32 rotate_int = 3;</code>
     */
    private int rotateInt;

    /**
     * <code>optional uint32 group_id = 9;</code>
     */
    private int groupId;

    /**
     * <code>optional .NewMapRot rogue_map = 7;</code>
     */
    private final NewMapRotOuterClass.NewMapRot rogueMap = NewMapRotOuterClass.NewMapRot.newInstance();

    /**
     * <code>optional .MotionInfo motion = 14;</code>
     */
    private final MotionInfoOuterClass.MotionInfo motion = MotionInfoOuterClass.MotionInfo.newInstance();

    private RotateMapCsReq() {
    }

    /**
     * @return a new empty instance of {@code RotateMapCsReq}
     */
    public static RotateMapCsReq newInstance() {
      return new RotateMapCsReq();
    }

    /**
     * <code>optional uint32 rotate_int = 3;</code>
     * @return whether the rotateInt field is set
     */
    public boolean hasRotateInt() {
      return (bitField0_ & 0x00000001) != 0;
    }

    /**
     * <code>optional uint32 rotate_int = 3;</code>
     * @return this
     */
    public RotateMapCsReq clearRotateInt() {
      bitField0_ &= ~0x00000001;
      rotateInt = 0;
      return this;
    }

    /**
     * <code>optional uint32 rotate_int = 3;</code>
     * @return the rotateInt
     */
    public int getRotateInt() {
      return rotateInt;
    }

    /**
     * <code>optional uint32 rotate_int = 3;</code>
     * @param value the rotateInt to set
     * @return this
     */
    public RotateMapCsReq setRotateInt(final int value) {
      bitField0_ |= 0x00000001;
      rotateInt = value;
      return this;
    }

    /**
     * <code>optional uint32 group_id = 9;</code>
     * @return whether the groupId field is set
     */
    public boolean hasGroupId() {
      return (bitField0_ & 0x00000002) != 0;
    }

    /**
     * <code>optional uint32 group_id = 9;</code>
     * @return this
     */
    public RotateMapCsReq clearGroupId() {
      bitField0_ &= ~0x00000002;
      groupId = 0;
      return this;
    }

    /**
     * <code>optional uint32 group_id = 9;</code>
     * @return the groupId
     */
    public int getGroupId() {
      return groupId;
    }

    /**
     * <code>optional uint32 group_id = 9;</code>
     * @param value the groupId to set
     * @return this
     */
    public RotateMapCsReq setGroupId(final int value) {
      bitField0_ |= 0x00000002;
      groupId = value;
      return this;
    }

    /**
     * <code>optional .NewMapRot rogue_map = 7;</code>
     * @return whether the rogueMap field is set
     */
    public boolean hasRogueMap() {
      return (bitField0_ & 0x00000004) != 0;
    }

    /**
     * <code>optional .NewMapRot rogue_map = 7;</code>
     * @return this
     */
    public RotateMapCsReq clearRogueMap() {
      bitField0_ &= ~0x00000004;
      rogueMap.clear();
      return this;
    }

    /**
     * <code>optional .NewMapRot rogue_map = 7;</code>
     *
     * This method returns the internal storage object without modifying any has state.
     * The returned object should not be modified and be treated as read-only.
     *
     * Use {@link #getMutableRogueMap()} if you want to modify it.
     *
     * @return internal storage object for reading
     */
    public NewMapRotOuterClass.NewMapRot getRogueMap() {
      return rogueMap;
    }

    /**
     * <code>optional .NewMapRot rogue_map = 7;</code>
     *
     * This method returns the internal storage object and sets the corresponding
     * has state. The returned object will become part of this message and its
     * contents may be modified as long as the has state is not cleared.
     *
     * @return internal storage object for modifications
     */
    public NewMapRotOuterClass.NewMapRot getMutableRogueMap() {
      bitField0_ |= 0x00000004;
      return rogueMap;
    }

    /**
     * <code>optional .NewMapRot rogue_map = 7;</code>
     * @param value the rogueMap to set
     * @return this
     */
    public RotateMapCsReq setRogueMap(final NewMapRotOuterClass.NewMapRot value) {
      bitField0_ |= 0x00000004;
      rogueMap.copyFrom(value);
      return this;
    }

    /**
     * <code>optional .MotionInfo motion = 14;</code>
     * @return whether the motion field is set
     */
    public boolean hasMotion() {
      return (bitField0_ & 0x00000008) != 0;
    }

    /**
     * <code>optional .MotionInfo motion = 14;</code>
     * @return this
     */
    public RotateMapCsReq clearMotion() {
      bitField0_ &= ~0x00000008;
      motion.clear();
      return this;
    }

    /**
     * <code>optional .MotionInfo motion = 14;</code>
     *
     * This method returns the internal storage object without modifying any has state.
     * The returned object should not be modified and be treated as read-only.
     *
     * Use {@link #getMutableMotion()} if you want to modify it.
     *
     * @return internal storage object for reading
     */
    public MotionInfoOuterClass.MotionInfo getMotion() {
      return motion;
    }

    /**
     * <code>optional .MotionInfo motion = 14;</code>
     *
     * This method returns the internal storage object and sets the corresponding
     * has state. The returned object will become part of this message and its
     * contents may be modified as long as the has state is not cleared.
     *
     * @return internal storage object for modifications
     */
    public MotionInfoOuterClass.MotionInfo getMutableMotion() {
      bitField0_ |= 0x00000008;
      return motion;
    }

    /**
     * <code>optional .MotionInfo motion = 14;</code>
     * @param value the motion to set
     * @return this
     */
    public RotateMapCsReq setMotion(final MotionInfoOuterClass.MotionInfo value) {
      bitField0_ |= 0x00000008;
      motion.copyFrom(value);
      return this;
    }

    @Override
    public RotateMapCsReq copyFrom(final RotateMapCsReq other) {
      cachedSize = other.cachedSize;
      if ((bitField0_ | other.bitField0_) != 0) {
        bitField0_ = other.bitField0_;
        rotateInt = other.rotateInt;
        groupId = other.groupId;
        rogueMap.copyFrom(other.rogueMap);
        motion.copyFrom(other.motion);
      }
      return this;
    }

    @Override
    public RotateMapCsReq mergeFrom(final RotateMapCsReq other) {
      if (other.isEmpty()) {
        return this;
      }
      cachedSize = -1;
      if (other.hasRotateInt()) {
        setRotateInt(other.rotateInt);
      }
      if (other.hasGroupId()) {
        setGroupId(other.groupId);
      }
      if (other.hasRogueMap()) {
        getMutableRogueMap().mergeFrom(other.rogueMap);
      }
      if (other.hasMotion()) {
        getMutableMotion().mergeFrom(other.motion);
      }
      return this;
    }

    @Override
    public RotateMapCsReq clear() {
      if (isEmpty()) {
        return this;
      }
      cachedSize = -1;
      bitField0_ = 0;
      rotateInt = 0;
      groupId = 0;
      rogueMap.clear();
      motion.clear();
      return this;
    }

    @Override
    public RotateMapCsReq clearQuick() {
      if (isEmpty()) {
        return this;
      }
      cachedSize = -1;
      bitField0_ = 0;
      rogueMap.clearQuick();
      motion.clearQuick();
      return this;
    }

    @Override
    public boolean equals(Object o) {
      if (o == this) {
        return true;
      }
      if (!(o instanceof RotateMapCsReq)) {
        return false;
      }
      RotateMapCsReq other = (RotateMapCsReq) o;
      return bitField0_ == other.bitField0_
        && (!hasRotateInt() || rotateInt == other.rotateInt)
        && (!hasGroupId() || groupId == other.groupId)
        && (!hasRogueMap() || rogueMap.equals(other.rogueMap))
        && (!hasMotion() || motion.equals(other.motion));
    }

    @Override
    public void writeTo(final ProtoSink output) throws IOException {
      if ((bitField0_ & 0x00000001) != 0) {
        output.writeRawByte((byte) 24);
        output.writeUInt32NoTag(rotateInt);
      }
      if ((bitField0_ & 0x00000002) != 0) {
        output.writeRawByte((byte) 72);
        output.writeUInt32NoTag(groupId);
      }
      if ((bitField0_ & 0x00000004) != 0) {
        output.writeRawByte((byte) 58);
        output.writeMessageNoTag(rogueMap);
      }
      if ((bitField0_ & 0x00000008) != 0) {
        output.writeRawByte((byte) 114);
        output.writeMessageNoTag(motion);
      }
    }

    @Override
    protected int computeSerializedSize() {
      int size = 0;
      if ((bitField0_ & 0x00000001) != 0) {
        size += 1 + ProtoSink.computeUInt32SizeNoTag(rotateInt);
      }
      if ((bitField0_ & 0x00000002) != 0) {
        size += 1 + ProtoSink.computeUInt32SizeNoTag(groupId);
      }
      if ((bitField0_ & 0x00000004) != 0) {
        size += 1 + ProtoSink.computeMessageSizeNoTag(rogueMap);
      }
      if ((bitField0_ & 0x00000008) != 0) {
        size += 1 + ProtoSink.computeMessageSizeNoTag(motion);
      }
      return size;
    }

    @Override
    @SuppressWarnings("fallthrough")
    public RotateMapCsReq mergeFrom(final ProtoSource input) throws IOException {
      // Enabled Fall-Through Optimization (QuickBuffers)
      int tag = input.readTag();
      while (true) {
        switch (tag) {
          case 24: {
            // rotateInt
            rotateInt = input.readUInt32();
            bitField0_ |= 0x00000001;
            tag = input.readTag();
            if (tag != 72) {
              break;
            }
          }
          case 72: {
            // groupId
            groupId = input.readUInt32();
            bitField0_ |= 0x00000002;
            tag = input.readTag();
            if (tag != 58) {
              break;
            }
          }
          case 58: {
            // rogueMap
            input.readMessage(rogueMap);
            bitField0_ |= 0x00000004;
            tag = input.readTag();
            if (tag != 114) {
              break;
            }
          }
          case 114: {
            // motion
            input.readMessage(motion);
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
        }
      }
    }

    @Override
    public void writeTo(final JsonSink output) throws IOException {
      output.beginObject();
      if ((bitField0_ & 0x00000001) != 0) {
        output.writeUInt32(FieldNames.rotateInt, rotateInt);
      }
      if ((bitField0_ & 0x00000002) != 0) {
        output.writeUInt32(FieldNames.groupId, groupId);
      }
      if ((bitField0_ & 0x00000004) != 0) {
        output.writeMessage(FieldNames.rogueMap, rogueMap);
      }
      if ((bitField0_ & 0x00000008) != 0) {
        output.writeMessage(FieldNames.motion, motion);
      }
      output.endObject();
    }

    @Override
    public RotateMapCsReq mergeFrom(final JsonSource input) throws IOException {
      if (!input.beginObject()) {
        return this;
      }
      while (!input.isAtEnd()) {
        switch (input.readFieldHash()) {
          case -1249476460:
          case -78414069: {
            if (input.isAtField(FieldNames.rotateInt)) {
              if (!input.trySkipNullValue()) {
                rotateInt = input.readUInt32();
                bitField0_ |= 0x00000001;
              }
            } else {
              input.skipUnknownField();
            }
            break;
          }
          case 293428218:
          case 506361563: {
            if (input.isAtField(FieldNames.groupId)) {
              if (!input.trySkipNullValue()) {
                groupId = input.readUInt32();
                bitField0_ |= 0x00000002;
              }
            } else {
              input.skipUnknownField();
            }
            break;
          }
          case -394483422:
          case 656463223: {
            if (input.isAtField(FieldNames.rogueMap)) {
              if (!input.trySkipNullValue()) {
                input.readMessage(rogueMap);
                bitField0_ |= 0x00000004;
              }
            } else {
              input.skipUnknownField();
            }
            break;
          }
          case -1068318794: {
            if (input.isAtField(FieldNames.motion)) {
              if (!input.trySkipNullValue()) {
                input.readMessage(motion);
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
    public RotateMapCsReq clone() {
      return new RotateMapCsReq().copyFrom(this);
    }

    @Override
    public boolean isEmpty() {
      return ((bitField0_) == 0);
    }

    public static RotateMapCsReq parseFrom(final byte[] data) throws
        InvalidProtocolBufferException {
      return ProtoMessage.mergeFrom(new RotateMapCsReq(), data).checkInitialized();
    }

    public static RotateMapCsReq parseFrom(final ProtoSource input) throws IOException {
      return ProtoMessage.mergeFrom(new RotateMapCsReq(), input).checkInitialized();
    }

    public static RotateMapCsReq parseFrom(final JsonSource input) throws IOException {
      return ProtoMessage.mergeFrom(new RotateMapCsReq(), input).checkInitialized();
    }

    /**
     * @return factory for creating RotateMapCsReq messages
     */
    public static MessageFactory<RotateMapCsReq> getFactory() {
      return RotateMapCsReqFactory.INSTANCE;
    }

    private enum RotateMapCsReqFactory implements MessageFactory<RotateMapCsReq> {
      INSTANCE;

      @Override
      public RotateMapCsReq create() {
        return RotateMapCsReq.newInstance();
      }
    }

    /**
     * Contains name constants used for serializing JSON
     */
    static class FieldNames {
      static final FieldName rotateInt = FieldName.forField("rotateInt", "rotate_int");

      static final FieldName groupId = FieldName.forField("groupId", "group_id");

      static final FieldName rogueMap = FieldName.forField("rogueMap", "rogue_map");

      static final FieldName motion = FieldName.forField("motion");
    }
  }
}
