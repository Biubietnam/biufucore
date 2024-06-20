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
import us.hebi.quickbuf.RepeatedMessage;
import us.hebi.quickbuf.Utf8String;

public final class BuffInfoOuterClass {
  /**
   * <pre>
   *  MDNJKGHICMH
   * </pre>
   *
   * Protobuf type {@code BuffInfo}
   */
  public static final class BuffInfo extends ProtoMessage<BuffInfo> implements Cloneable {
    private static final long serialVersionUID = 0L;

    /**
     * <pre>
     *  uint32 CMPGFJCGFAN = 8;
     * </pre>
     *
     * <code>optional uint64 add_time_ms = 15;</code>
     */
    private long addTimeMs;

    /**
     * <pre>
     *  EDINNBPPOGG
     * </pre>
     *
     * <code>optional float life_time = 3;</code>
     */
    private float lifeTime;

    /**
     * <code>optional uint32 scene_avatar_id = 5;</code>
     */
    private int sceneAvatarId;

    /**
     * <pre>
     *  uint32 FIDELEDGGEH = 13;
     *  uint32 JGDMLOFCNCH = 3;
     * </pre>
     *
     * <code>optional uint32 level = 7;</code>
     */
    private int level;

    /**
     * <pre>
     * ?
     * </pre>
     *
     * <code>optional uint32 buff_id = 8;</code>
     */
    private int buffId;

    /**
     * <pre>
     * ?
     * </pre>
     *
     * <code>optional uint32 count = 13;</code>
     */
    private int count;

    /**
     * <pre>
     *  PFIFNDLINMC
     * </pre>
     *
     * <code>repeated .BuffInfo.DynamicValuesEntry dynamic_values = 4;</code>
     */
    private final RepeatedMessage<DynamicValuesEntry> dynamicValues = RepeatedMessage.newEmptyInstance(DynamicValuesEntry.getFactory());

    private BuffInfo() {
    }

    /**
     * <pre>
     *  MDNJKGHICMH
     * </pre>
     *
     * @return a new empty instance of {@code BuffInfo}
     */
    public static BuffInfo newInstance() {
      return new BuffInfo();
    }

    /**
     * <pre>
     *  uint32 CMPGFJCGFAN = 8;
     * </pre>
     *
     * <code>optional uint64 add_time_ms = 15;</code>
     * @return whether the addTimeMs field is set
     */
    public boolean hasAddTimeMs() {
      return (bitField0_ & 0x00000001) != 0;
    }

    /**
     * <pre>
     *  uint32 CMPGFJCGFAN = 8;
     * </pre>
     *
     * <code>optional uint64 add_time_ms = 15;</code>
     * @return this
     */
    public BuffInfo clearAddTimeMs() {
      bitField0_ &= ~0x00000001;
      addTimeMs = 0L;
      return this;
    }

    /**
     * <pre>
     *  uint32 CMPGFJCGFAN = 8;
     * </pre>
     *
     * <code>optional uint64 add_time_ms = 15;</code>
     * @return the addTimeMs
     */
    public long getAddTimeMs() {
      return addTimeMs;
    }

    /**
     * <pre>
     *  uint32 CMPGFJCGFAN = 8;
     * </pre>
     *
     * <code>optional uint64 add_time_ms = 15;</code>
     * @param value the addTimeMs to set
     * @return this
     */
    public BuffInfo setAddTimeMs(final long value) {
      bitField0_ |= 0x00000001;
      addTimeMs = value;
      return this;
    }

    /**
     * <pre>
     *  EDINNBPPOGG
     * </pre>
     *
     * <code>optional float life_time = 3;</code>
     * @return whether the lifeTime field is set
     */
    public boolean hasLifeTime() {
      return (bitField0_ & 0x00000002) != 0;
    }

    /**
     * <pre>
     *  EDINNBPPOGG
     * </pre>
     *
     * <code>optional float life_time = 3;</code>
     * @return this
     */
    public BuffInfo clearLifeTime() {
      bitField0_ &= ~0x00000002;
      lifeTime = 0F;
      return this;
    }

    /**
     * <pre>
     *  EDINNBPPOGG
     * </pre>
     *
     * <code>optional float life_time = 3;</code>
     * @return the lifeTime
     */
    public float getLifeTime() {
      return lifeTime;
    }

    /**
     * <pre>
     *  EDINNBPPOGG
     * </pre>
     *
     * <code>optional float life_time = 3;</code>
     * @param value the lifeTime to set
     * @return this
     */
    public BuffInfo setLifeTime(final float value) {
      bitField0_ |= 0x00000002;
      lifeTime = value;
      return this;
    }

    /**
     * <code>optional uint32 scene_avatar_id = 5;</code>
     * @return whether the sceneAvatarId field is set
     */
    public boolean hasSceneAvatarId() {
      return (bitField0_ & 0x00000004) != 0;
    }

    /**
     * <code>optional uint32 scene_avatar_id = 5;</code>
     * @return this
     */
    public BuffInfo clearSceneAvatarId() {
      bitField0_ &= ~0x00000004;
      sceneAvatarId = 0;
      return this;
    }

    /**
     * <code>optional uint32 scene_avatar_id = 5;</code>
     * @return the sceneAvatarId
     */
    public int getSceneAvatarId() {
      return sceneAvatarId;
    }

    /**
     * <code>optional uint32 scene_avatar_id = 5;</code>
     * @param value the sceneAvatarId to set
     * @return this
     */
    public BuffInfo setSceneAvatarId(final int value) {
      bitField0_ |= 0x00000004;
      sceneAvatarId = value;
      return this;
    }

    /**
     * <pre>
     *  uint32 FIDELEDGGEH = 13;
     *  uint32 JGDMLOFCNCH = 3;
     * </pre>
     *
     * <code>optional uint32 level = 7;</code>
     * @return whether the level field is set
     */
    public boolean hasLevel() {
      return (bitField0_ & 0x00000008) != 0;
    }

    /**
     * <pre>
     *  uint32 FIDELEDGGEH = 13;
     *  uint32 JGDMLOFCNCH = 3;
     * </pre>
     *
     * <code>optional uint32 level = 7;</code>
     * @return this
     */
    public BuffInfo clearLevel() {
      bitField0_ &= ~0x00000008;
      level = 0;
      return this;
    }

    /**
     * <pre>
     *  uint32 FIDELEDGGEH = 13;
     *  uint32 JGDMLOFCNCH = 3;
     * </pre>
     *
     * <code>optional uint32 level = 7;</code>
     * @return the level
     */
    public int getLevel() {
      return level;
    }

    /**
     * <pre>
     *  uint32 FIDELEDGGEH = 13;
     *  uint32 JGDMLOFCNCH = 3;
     * </pre>
     *
     * <code>optional uint32 level = 7;</code>
     * @param value the level to set
     * @return this
     */
    public BuffInfo setLevel(final int value) {
      bitField0_ |= 0x00000008;
      level = value;
      return this;
    }

    /**
     * <pre>
     * ?
     * </pre>
     *
     * <code>optional uint32 buff_id = 8;</code>
     * @return whether the buffId field is set
     */
    public boolean hasBuffId() {
      return (bitField0_ & 0x00000010) != 0;
    }

    /**
     * <pre>
     * ?
     * </pre>
     *
     * <code>optional uint32 buff_id = 8;</code>
     * @return this
     */
    public BuffInfo clearBuffId() {
      bitField0_ &= ~0x00000010;
      buffId = 0;
      return this;
    }

    /**
     * <pre>
     * ?
     * </pre>
     *
     * <code>optional uint32 buff_id = 8;</code>
     * @return the buffId
     */
    public int getBuffId() {
      return buffId;
    }

    /**
     * <pre>
     * ?
     * </pre>
     *
     * <code>optional uint32 buff_id = 8;</code>
     * @param value the buffId to set
     * @return this
     */
    public BuffInfo setBuffId(final int value) {
      bitField0_ |= 0x00000010;
      buffId = value;
      return this;
    }

    /**
     * <pre>
     * ?
     * </pre>
     *
     * <code>optional uint32 count = 13;</code>
     * @return whether the count field is set
     */
    public boolean hasCount() {
      return (bitField0_ & 0x00000020) != 0;
    }

    /**
     * <pre>
     * ?
     * </pre>
     *
     * <code>optional uint32 count = 13;</code>
     * @return this
     */
    public BuffInfo clearCount() {
      bitField0_ &= ~0x00000020;
      count = 0;
      return this;
    }

    /**
     * <pre>
     * ?
     * </pre>
     *
     * <code>optional uint32 count = 13;</code>
     * @return the count
     */
    public int getCount() {
      return count;
    }

    /**
     * <pre>
     * ?
     * </pre>
     *
     * <code>optional uint32 count = 13;</code>
     * @param value the count to set
     * @return this
     */
    public BuffInfo setCount(final int value) {
      bitField0_ |= 0x00000020;
      count = value;
      return this;
    }

    /**
     * <pre>
     *  PFIFNDLINMC
     * </pre>
     *
     * <code>repeated .BuffInfo.DynamicValuesEntry dynamic_values = 4;</code>
     * @return whether the dynamicValues field is set
     */
    public boolean hasDynamicValues() {
      return (bitField0_ & 0x00000040) != 0;
    }

    /**
     * <pre>
     *  PFIFNDLINMC
     * </pre>
     *
     * <code>repeated .BuffInfo.DynamicValuesEntry dynamic_values = 4;</code>
     * @return this
     */
    public BuffInfo clearDynamicValues() {
      bitField0_ &= ~0x00000040;
      dynamicValues.clear();
      return this;
    }

    /**
     * <pre>
     *  PFIFNDLINMC
     * </pre>
     *
     * <code>repeated .BuffInfo.DynamicValuesEntry dynamic_values = 4;</code>
     *
     * This method returns the internal storage object without modifying any has state.
     * The returned object should not be modified and be treated as read-only.
     *
     * Use {@link #getMutableDynamicValues()} if you want to modify it.
     *
     * @return internal storage object for reading
     */
    public RepeatedMessage<DynamicValuesEntry> getDynamicValues() {
      return dynamicValues;
    }

    /**
     * <pre>
     *  PFIFNDLINMC
     * </pre>
     *
     * <code>repeated .BuffInfo.DynamicValuesEntry dynamic_values = 4;</code>
     *
     * This method returns the internal storage object and sets the corresponding
     * has state. The returned object will become part of this message and its
     * contents may be modified as long as the has state is not cleared.
     *
     * @return internal storage object for modifications
     */
    public RepeatedMessage<DynamicValuesEntry> getMutableDynamicValues() {
      bitField0_ |= 0x00000040;
      return dynamicValues;
    }

    /**
     * <pre>
     *  PFIFNDLINMC
     * </pre>
     *
     * <code>repeated .BuffInfo.DynamicValuesEntry dynamic_values = 4;</code>
     * @param value the dynamicValues to add
     * @return this
     */
    public BuffInfo addDynamicValues(final DynamicValuesEntry value) {
      bitField0_ |= 0x00000040;
      dynamicValues.add(value);
      return this;
    }

    /**
     * <pre>
     *  PFIFNDLINMC
     * </pre>
     *
     * <code>repeated .BuffInfo.DynamicValuesEntry dynamic_values = 4;</code>
     * @param values the dynamicValues to add
     * @return this
     */
    public BuffInfo addAllDynamicValues(final DynamicValuesEntry... values) {
      bitField0_ |= 0x00000040;
      dynamicValues.addAll(values);
      return this;
    }

    @Override
    public BuffInfo copyFrom(final BuffInfo other) {
      cachedSize = other.cachedSize;
      if ((bitField0_ | other.bitField0_) != 0) {
        bitField0_ = other.bitField0_;
        addTimeMs = other.addTimeMs;
        lifeTime = other.lifeTime;
        sceneAvatarId = other.sceneAvatarId;
        level = other.level;
        buffId = other.buffId;
        count = other.count;
        dynamicValues.copyFrom(other.dynamicValues);
      }
      return this;
    }

    @Override
    public BuffInfo mergeFrom(final BuffInfo other) {
      if (other.isEmpty()) {
        return this;
      }
      cachedSize = -1;
      if (other.hasAddTimeMs()) {
        setAddTimeMs(other.addTimeMs);
      }
      if (other.hasLifeTime()) {
        setLifeTime(other.lifeTime);
      }
      if (other.hasSceneAvatarId()) {
        setSceneAvatarId(other.sceneAvatarId);
      }
      if (other.hasLevel()) {
        setLevel(other.level);
      }
      if (other.hasBuffId()) {
        setBuffId(other.buffId);
      }
      if (other.hasCount()) {
        setCount(other.count);
      }
      if (other.hasDynamicValues()) {
        getMutableDynamicValues().addAll(other.dynamicValues);
      }
      return this;
    }

    @Override
    public BuffInfo clear() {
      if (isEmpty()) {
        return this;
      }
      cachedSize = -1;
      bitField0_ = 0;
      addTimeMs = 0L;
      lifeTime = 0F;
      sceneAvatarId = 0;
      level = 0;
      buffId = 0;
      count = 0;
      dynamicValues.clear();
      return this;
    }

    @Override
    public BuffInfo clearQuick() {
      if (isEmpty()) {
        return this;
      }
      cachedSize = -1;
      bitField0_ = 0;
      dynamicValues.clearQuick();
      return this;
    }

    @Override
    public boolean equals(Object o) {
      if (o == this) {
        return true;
      }
      if (!(o instanceof BuffInfo)) {
        return false;
      }
      BuffInfo other = (BuffInfo) o;
      return bitField0_ == other.bitField0_
        && (!hasAddTimeMs() || addTimeMs == other.addTimeMs)
        && (!hasLifeTime() || ProtoUtil.isEqual(lifeTime, other.lifeTime))
        && (!hasSceneAvatarId() || sceneAvatarId == other.sceneAvatarId)
        && (!hasLevel() || level == other.level)
        && (!hasBuffId() || buffId == other.buffId)
        && (!hasCount() || count == other.count)
        && (!hasDynamicValues() || dynamicValues.equals(other.dynamicValues));
    }

    @Override
    public void writeTo(final ProtoSink output) throws IOException {
      if ((bitField0_ & 0x00000001) != 0) {
        output.writeRawByte((byte) 120);
        output.writeUInt64NoTag(addTimeMs);
      }
      if ((bitField0_ & 0x00000002) != 0) {
        output.writeRawByte((byte) 29);
        output.writeFloatNoTag(lifeTime);
      }
      if ((bitField0_ & 0x00000004) != 0) {
        output.writeRawByte((byte) 40);
        output.writeUInt32NoTag(sceneAvatarId);
      }
      if ((bitField0_ & 0x00000008) != 0) {
        output.writeRawByte((byte) 56);
        output.writeUInt32NoTag(level);
      }
      if ((bitField0_ & 0x00000010) != 0) {
        output.writeRawByte((byte) 64);
        output.writeUInt32NoTag(buffId);
      }
      if ((bitField0_ & 0x00000020) != 0) {
        output.writeRawByte((byte) 104);
        output.writeUInt32NoTag(count);
      }
      if ((bitField0_ & 0x00000040) != 0) {
        for (int i = 0; i < dynamicValues.length(); i++) {
          output.writeRawByte((byte) 34);
          output.writeMessageNoTag(dynamicValues.get(i));
        }
      }
    }

    @Override
    protected int computeSerializedSize() {
      int size = 0;
      if ((bitField0_ & 0x00000001) != 0) {
        size += 1 + ProtoSink.computeUInt64SizeNoTag(addTimeMs);
      }
      if ((bitField0_ & 0x00000002) != 0) {
        size += 5;
      }
      if ((bitField0_ & 0x00000004) != 0) {
        size += 1 + ProtoSink.computeUInt32SizeNoTag(sceneAvatarId);
      }
      if ((bitField0_ & 0x00000008) != 0) {
        size += 1 + ProtoSink.computeUInt32SizeNoTag(level);
      }
      if ((bitField0_ & 0x00000010) != 0) {
        size += 1 + ProtoSink.computeUInt32SizeNoTag(buffId);
      }
      if ((bitField0_ & 0x00000020) != 0) {
        size += 1 + ProtoSink.computeUInt32SizeNoTag(count);
      }
      if ((bitField0_ & 0x00000040) != 0) {
        size += (1 * dynamicValues.length()) + ProtoSink.computeRepeatedMessageSizeNoTag(dynamicValues);
      }
      return size;
    }

    @Override
    @SuppressWarnings("fallthrough")
    public BuffInfo mergeFrom(final ProtoSource input) throws IOException {
      // Enabled Fall-Through Optimization (QuickBuffers)
      int tag = input.readTag();
      while (true) {
        switch (tag) {
          case 120: {
            // addTimeMs
            addTimeMs = input.readUInt64();
            bitField0_ |= 0x00000001;
            tag = input.readTag();
            if (tag != 29) {
              break;
            }
          }
          case 29: {
            // lifeTime
            lifeTime = input.readFloat();
            bitField0_ |= 0x00000002;
            tag = input.readTag();
            if (tag != 40) {
              break;
            }
          }
          case 40: {
            // sceneAvatarId
            sceneAvatarId = input.readUInt32();
            bitField0_ |= 0x00000004;
            tag = input.readTag();
            if (tag != 56) {
              break;
            }
          }
          case 56: {
            // level
            level = input.readUInt32();
            bitField0_ |= 0x00000008;
            tag = input.readTag();
            if (tag != 64) {
              break;
            }
          }
          case 64: {
            // buffId
            buffId = input.readUInt32();
            bitField0_ |= 0x00000010;
            tag = input.readTag();
            if (tag != 104) {
              break;
            }
          }
          case 104: {
            // count
            count = input.readUInt32();
            bitField0_ |= 0x00000020;
            tag = input.readTag();
            if (tag != 34) {
              break;
            }
          }
          case 34: {
            // dynamicValues
            tag = input.readRepeatedMessage(dynamicValues, tag);
            bitField0_ |= 0x00000040;
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
        output.writeUInt64(FieldNames.addTimeMs, addTimeMs);
      }
      if ((bitField0_ & 0x00000002) != 0) {
        output.writeFloat(FieldNames.lifeTime, lifeTime);
      }
      if ((bitField0_ & 0x00000004) != 0) {
        output.writeUInt32(FieldNames.sceneAvatarId, sceneAvatarId);
      }
      if ((bitField0_ & 0x00000008) != 0) {
        output.writeUInt32(FieldNames.level, level);
      }
      if ((bitField0_ & 0x00000010) != 0) {
        output.writeUInt32(FieldNames.buffId, buffId);
      }
      if ((bitField0_ & 0x00000020) != 0) {
        output.writeUInt32(FieldNames.count, count);
      }
      if ((bitField0_ & 0x00000040) != 0) {
        output.writeRepeatedMessage(FieldNames.dynamicValues, dynamicValues);
      }
      output.endObject();
    }

    @Override
    public BuffInfo mergeFrom(final JsonSource input) throws IOException {
      if (!input.beginObject()) {
        return this;
      }
      while (!input.isAtEnd()) {
        switch (input.readFieldHash()) {
          case 19170644:
          case 5373626: {
            if (input.isAtField(FieldNames.addTimeMs)) {
              if (!input.trySkipNullValue()) {
                addTimeMs = input.readUInt64();
                bitField0_ |= 0x00000001;
              }
            } else {
              input.skipUnknownField();
            }
            break;
          }
          case 959617001:
          case -306161104: {
            if (input.isAtField(FieldNames.lifeTime)) {
              if (!input.trySkipNullValue()) {
                lifeTime = input.readFloat();
                bitField0_ |= 0x00000002;
              }
            } else {
              input.skipUnknownField();
            }
            break;
          }
          case -1044772608:
          case 1783323086: {
            if (input.isAtField(FieldNames.sceneAvatarId)) {
              if (!input.trySkipNullValue()) {
                sceneAvatarId = input.readUInt32();
                bitField0_ |= 0x00000004;
              }
            } else {
              input.skipUnknownField();
            }
            break;
          }
          case 102865796: {
            if (input.isAtField(FieldNames.level)) {
              if (!input.trySkipNullValue()) {
                level = input.readUInt32();
                bitField0_ |= 0x00000008;
              }
            } else {
              input.skipUnknownField();
            }
            break;
          }
          case -1378119474:
          case 227990663: {
            if (input.isAtField(FieldNames.buffId)) {
              if (!input.trySkipNullValue()) {
                buffId = input.readUInt32();
                bitField0_ |= 0x00000010;
              }
            } else {
              input.skipUnknownField();
            }
            break;
          }
          case 94851343: {
            if (input.isAtField(FieldNames.count)) {
              if (!input.trySkipNullValue()) {
                count = input.readUInt32();
                bitField0_ |= 0x00000020;
              }
            } else {
              input.skipUnknownField();
            }
            break;
          }
          case 571506241:
          case 525223202: {
            if (input.isAtField(FieldNames.dynamicValues)) {
              if (!input.trySkipNullValue()) {
                input.readRepeatedMessage(dynamicValues);
                bitField0_ |= 0x00000040;
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
    public BuffInfo clone() {
      return new BuffInfo().copyFrom(this);
    }

    @Override
    public boolean isEmpty() {
      return ((bitField0_) == 0);
    }

    public static BuffInfo parseFrom(final byte[] data) throws InvalidProtocolBufferException {
      return ProtoMessage.mergeFrom(new BuffInfo(), data).checkInitialized();
    }

    public static BuffInfo parseFrom(final ProtoSource input) throws IOException {
      return ProtoMessage.mergeFrom(new BuffInfo(), input).checkInitialized();
    }

    public static BuffInfo parseFrom(final JsonSource input) throws IOException {
      return ProtoMessage.mergeFrom(new BuffInfo(), input).checkInitialized();
    }

    /**
     * @return factory for creating BuffInfo messages
     */
    public static MessageFactory<BuffInfo> getFactory() {
      return BuffInfoFactory.INSTANCE;
    }

    /**
     * Protobuf type {@code DynamicValuesEntry}
     */
    public static final class DynamicValuesEntry extends ProtoMessage<DynamicValuesEntry> implements Cloneable {
      private static final long serialVersionUID = 0L;

      /**
       * <code>optional float value = 2;</code>
       */
      private float value_;

      /**
       * <code>optional string key = 1;</code>
       */
      private final Utf8String key = Utf8String.newEmptyInstance();

      private DynamicValuesEntry() {
      }

      /**
       * @return a new empty instance of {@code DynamicValuesEntry}
       */
      public static DynamicValuesEntry newInstance() {
        return new DynamicValuesEntry();
      }

      /**
       * <code>optional float value = 2;</code>
       * @return whether the value_ field is set
       */
      public boolean hasValue() {
        return (bitField0_ & 0x00000001) != 0;
      }

      /**
       * <code>optional float value = 2;</code>
       * @return this
       */
      public DynamicValuesEntry clearValue() {
        bitField0_ &= ~0x00000001;
        value_ = 0F;
        return this;
      }

      /**
       * <code>optional float value = 2;</code>
       * @return the value_
       */
      public float getValue() {
        return value_;
      }

      /**
       * <code>optional float value = 2;</code>
       * @param value the value_ to set
       * @return this
       */
      public DynamicValuesEntry setValue(final float value) {
        bitField0_ |= 0x00000001;
        value_ = value;
        return this;
      }

      /**
       * <code>optional string key = 1;</code>
       * @return whether the key field is set
       */
      public boolean hasKey() {
        return (bitField0_ & 0x00000002) != 0;
      }

      /**
       * <code>optional string key = 1;</code>
       * @return this
       */
      public DynamicValuesEntry clearKey() {
        bitField0_ &= ~0x00000002;
        key.clear();
        return this;
      }

      /**
       * <code>optional string key = 1;</code>
       * @return the key
       */
      public String getKey() {
        return key.getString();
      }

      /**
       * <code>optional string key = 1;</code>
       * @return internal {@code Utf8String} representation of key for reading
       */
      public Utf8String getKeyBytes() {
        return this.key;
      }

      /**
       * <code>optional string key = 1;</code>
       * @return internal {@code Utf8String} representation of key for modifications
       */
      public Utf8String getMutableKeyBytes() {
        bitField0_ |= 0x00000002;
        return this.key;
      }

      /**
       * <code>optional string key = 1;</code>
       * @param value the key to set
       * @return this
       */
      public DynamicValuesEntry setKey(final CharSequence value) {
        bitField0_ |= 0x00000002;
        key.copyFrom(value);
        return this;
      }

      /**
       * <code>optional string key = 1;</code>
       * @param value the key to set
       * @return this
       */
      public DynamicValuesEntry setKey(final Utf8String value) {
        bitField0_ |= 0x00000002;
        key.copyFrom(value);
        return this;
      }

      @Override
      public DynamicValuesEntry copyFrom(final DynamicValuesEntry other) {
        cachedSize = other.cachedSize;
        if ((bitField0_ | other.bitField0_) != 0) {
          bitField0_ = other.bitField0_;
          value_ = other.value_;
          key.copyFrom(other.key);
        }
        return this;
      }

      @Override
      public DynamicValuesEntry mergeFrom(final DynamicValuesEntry other) {
        if (other.isEmpty()) {
          return this;
        }
        cachedSize = -1;
        if (other.hasValue()) {
          setValue(other.value_);
        }
        if (other.hasKey()) {
          getMutableKeyBytes().copyFrom(other.key);
        }
        return this;
      }

      @Override
      public DynamicValuesEntry clear() {
        if (isEmpty()) {
          return this;
        }
        cachedSize = -1;
        bitField0_ = 0;
        value_ = 0F;
        key.clear();
        return this;
      }

      @Override
      public DynamicValuesEntry clearQuick() {
        if (isEmpty()) {
          return this;
        }
        cachedSize = -1;
        bitField0_ = 0;
        key.clear();
        return this;
      }

      @Override
      public boolean equals(Object o) {
        if (o == this) {
          return true;
        }
        if (!(o instanceof DynamicValuesEntry)) {
          return false;
        }
        DynamicValuesEntry other = (DynamicValuesEntry) o;
        return bitField0_ == other.bitField0_
          && (!hasValue() || ProtoUtil.isEqual(value_, other.value_))
          && (!hasKey() || key.equals(other.key));
      }

      @Override
      public void writeTo(final ProtoSink output) throws IOException {
        if ((bitField0_ & 0x00000001) != 0) {
          output.writeRawByte((byte) 21);
          output.writeFloatNoTag(value_);
        }
        if ((bitField0_ & 0x00000002) != 0) {
          output.writeRawByte((byte) 10);
          output.writeStringNoTag(key);
        }
      }

      @Override
      protected int computeSerializedSize() {
        int size = 0;
        if ((bitField0_ & 0x00000001) != 0) {
          size += 5;
        }
        if ((bitField0_ & 0x00000002) != 0) {
          size += 1 + ProtoSink.computeStringSizeNoTag(key);
        }
        return size;
      }

      @Override
      @SuppressWarnings("fallthrough")
      public DynamicValuesEntry mergeFrom(final ProtoSource input) throws IOException {
        // Enabled Fall-Through Optimization (QuickBuffers)
        int tag = input.readTag();
        while (true) {
          switch (tag) {
            case 21: {
              // value_
              value_ = input.readFloat();
              bitField0_ |= 0x00000001;
              tag = input.readTag();
              if (tag != 10) {
                break;
              }
            }
            case 10: {
              // key
              input.readString(key);
              bitField0_ |= 0x00000002;
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
          output.writeFloat(FieldNames.value_, value_);
        }
        if ((bitField0_ & 0x00000002) != 0) {
          output.writeString(FieldNames.key, key);
        }
        output.endObject();
      }

      @Override
      public DynamicValuesEntry mergeFrom(final JsonSource input) throws IOException {
        if (!input.beginObject()) {
          return this;
        }
        while (!input.isAtEnd()) {
          switch (input.readFieldHash()) {
            case 111972721: {
              if (input.isAtField(FieldNames.value_)) {
                if (!input.trySkipNullValue()) {
                  value_ = input.readFloat();
                  bitField0_ |= 0x00000001;
                }
              } else {
                input.skipUnknownField();
              }
              break;
            }
            case 106079: {
              if (input.isAtField(FieldNames.key)) {
                if (!input.trySkipNullValue()) {
                  input.readString(key);
                  bitField0_ |= 0x00000002;
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
      public DynamicValuesEntry clone() {
        return new DynamicValuesEntry().copyFrom(this);
      }

      @Override
      public boolean isEmpty() {
        return ((bitField0_) == 0);
      }

      public static DynamicValuesEntry parseFrom(final byte[] data) throws
          InvalidProtocolBufferException {
        return ProtoMessage.mergeFrom(new DynamicValuesEntry(), data).checkInitialized();
      }

      public static DynamicValuesEntry parseFrom(final ProtoSource input) throws IOException {
        return ProtoMessage.mergeFrom(new DynamicValuesEntry(), input).checkInitialized();
      }

      public static DynamicValuesEntry parseFrom(final JsonSource input) throws IOException {
        return ProtoMessage.mergeFrom(new DynamicValuesEntry(), input).checkInitialized();
      }

      /**
       * @return factory for creating DynamicValuesEntry messages
       */
      public static MessageFactory<DynamicValuesEntry> getFactory() {
        return DynamicValuesEntryFactory.INSTANCE;
      }

      private enum DynamicValuesEntryFactory implements MessageFactory<DynamicValuesEntry> {
        INSTANCE;

        @Override
        public DynamicValuesEntry create() {
          return DynamicValuesEntry.newInstance();
        }
      }

      /**
       * Contains name constants used for serializing JSON
       */
      static class FieldNames {
        static final FieldName value_ = FieldName.forField("value");

        static final FieldName key = FieldName.forField("key");
      }
    }

    private enum BuffInfoFactory implements MessageFactory<BuffInfo> {
      INSTANCE;

      @Override
      public BuffInfo create() {
        return BuffInfo.newInstance();
      }
    }

    /**
     * Contains name constants used for serializing JSON
     */
    static class FieldNames {
      static final FieldName addTimeMs = FieldName.forField("addTimeMs", "add_time_ms");

      static final FieldName lifeTime = FieldName.forField("lifeTime", "life_time");

      static final FieldName sceneAvatarId = FieldName.forField("sceneAvatarId", "scene_avatar_id");

      static final FieldName level = FieldName.forField("level");

      static final FieldName buffId = FieldName.forField("buffId", "buff_id");

      static final FieldName count = FieldName.forField("count");

      static final FieldName dynamicValues = FieldName.forField("dynamicValues", "dynamic_values");
    }
  }
}
