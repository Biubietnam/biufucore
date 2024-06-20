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

public final class BlackInfoOuterClass {
  /**
   * Protobuf type {@code BlackInfo}
   */
  public static final class BlackInfo extends ProtoMessage<BlackInfo> implements Cloneable {
    private static final long serialVersionUID = 0L;

    /**
     * <code>optional int64 begin_time = 1;</code>
     */
    private long beginTime;

    /**
     * <code>optional int64 end_time = 2;</code>
     */
    private long endTime;

    /**
     * <pre>
     *  EAMPPBLEIHN
     * </pre>
     *
     * <code>optional uint32 limit_level = 3;</code>
     */
    private int limitLevel;

    /**
     * <pre>
     *  PLENLGFHJIJ
     * </pre>
     *
     * <code>optional uint32 ban_type = 4;</code>
     */
    private int banType;

    private BlackInfo() {
    }

    /**
     * @return a new empty instance of {@code BlackInfo}
     */
    public static BlackInfo newInstance() {
      return new BlackInfo();
    }

    /**
     * <code>optional int64 begin_time = 1;</code>
     * @return whether the beginTime field is set
     */
    public boolean hasBeginTime() {
      return (bitField0_ & 0x00000001) != 0;
    }

    /**
     * <code>optional int64 begin_time = 1;</code>
     * @return this
     */
    public BlackInfo clearBeginTime() {
      bitField0_ &= ~0x00000001;
      beginTime = 0L;
      return this;
    }

    /**
     * <code>optional int64 begin_time = 1;</code>
     * @return the beginTime
     */
    public long getBeginTime() {
      return beginTime;
    }

    /**
     * <code>optional int64 begin_time = 1;</code>
     * @param value the beginTime to set
     * @return this
     */
    public BlackInfo setBeginTime(final long value) {
      bitField0_ |= 0x00000001;
      beginTime = value;
      return this;
    }

    /**
     * <code>optional int64 end_time = 2;</code>
     * @return whether the endTime field is set
     */
    public boolean hasEndTime() {
      return (bitField0_ & 0x00000002) != 0;
    }

    /**
     * <code>optional int64 end_time = 2;</code>
     * @return this
     */
    public BlackInfo clearEndTime() {
      bitField0_ &= ~0x00000002;
      endTime = 0L;
      return this;
    }

    /**
     * <code>optional int64 end_time = 2;</code>
     * @return the endTime
     */
    public long getEndTime() {
      return endTime;
    }

    /**
     * <code>optional int64 end_time = 2;</code>
     * @param value the endTime to set
     * @return this
     */
    public BlackInfo setEndTime(final long value) {
      bitField0_ |= 0x00000002;
      endTime = value;
      return this;
    }

    /**
     * <pre>
     *  EAMPPBLEIHN
     * </pre>
     *
     * <code>optional uint32 limit_level = 3;</code>
     * @return whether the limitLevel field is set
     */
    public boolean hasLimitLevel() {
      return (bitField0_ & 0x00000004) != 0;
    }

    /**
     * <pre>
     *  EAMPPBLEIHN
     * </pre>
     *
     * <code>optional uint32 limit_level = 3;</code>
     * @return this
     */
    public BlackInfo clearLimitLevel() {
      bitField0_ &= ~0x00000004;
      limitLevel = 0;
      return this;
    }

    /**
     * <pre>
     *  EAMPPBLEIHN
     * </pre>
     *
     * <code>optional uint32 limit_level = 3;</code>
     * @return the limitLevel
     */
    public int getLimitLevel() {
      return limitLevel;
    }

    /**
     * <pre>
     *  EAMPPBLEIHN
     * </pre>
     *
     * <code>optional uint32 limit_level = 3;</code>
     * @param value the limitLevel to set
     * @return this
     */
    public BlackInfo setLimitLevel(final int value) {
      bitField0_ |= 0x00000004;
      limitLevel = value;
      return this;
    }

    /**
     * <pre>
     *  PLENLGFHJIJ
     * </pre>
     *
     * <code>optional uint32 ban_type = 4;</code>
     * @return whether the banType field is set
     */
    public boolean hasBanType() {
      return (bitField0_ & 0x00000008) != 0;
    }

    /**
     * <pre>
     *  PLENLGFHJIJ
     * </pre>
     *
     * <code>optional uint32 ban_type = 4;</code>
     * @return this
     */
    public BlackInfo clearBanType() {
      bitField0_ &= ~0x00000008;
      banType = 0;
      return this;
    }

    /**
     * <pre>
     *  PLENLGFHJIJ
     * </pre>
     *
     * <code>optional uint32 ban_type = 4;</code>
     * @return the banType
     */
    public int getBanType() {
      return banType;
    }

    /**
     * <pre>
     *  PLENLGFHJIJ
     * </pre>
     *
     * <code>optional uint32 ban_type = 4;</code>
     * @param value the banType to set
     * @return this
     */
    public BlackInfo setBanType(final int value) {
      bitField0_ |= 0x00000008;
      banType = value;
      return this;
    }

    @Override
    public BlackInfo copyFrom(final BlackInfo other) {
      cachedSize = other.cachedSize;
      if ((bitField0_ | other.bitField0_) != 0) {
        bitField0_ = other.bitField0_;
        beginTime = other.beginTime;
        endTime = other.endTime;
        limitLevel = other.limitLevel;
        banType = other.banType;
      }
      return this;
    }

    @Override
    public BlackInfo mergeFrom(final BlackInfo other) {
      if (other.isEmpty()) {
        return this;
      }
      cachedSize = -1;
      if (other.hasBeginTime()) {
        setBeginTime(other.beginTime);
      }
      if (other.hasEndTime()) {
        setEndTime(other.endTime);
      }
      if (other.hasLimitLevel()) {
        setLimitLevel(other.limitLevel);
      }
      if (other.hasBanType()) {
        setBanType(other.banType);
      }
      return this;
    }

    @Override
    public BlackInfo clear() {
      if (isEmpty()) {
        return this;
      }
      cachedSize = -1;
      bitField0_ = 0;
      beginTime = 0L;
      endTime = 0L;
      limitLevel = 0;
      banType = 0;
      return this;
    }

    @Override
    public BlackInfo clearQuick() {
      if (isEmpty()) {
        return this;
      }
      cachedSize = -1;
      bitField0_ = 0;
      return this;
    }

    @Override
    public boolean equals(Object o) {
      if (o == this) {
        return true;
      }
      if (!(o instanceof BlackInfo)) {
        return false;
      }
      BlackInfo other = (BlackInfo) o;
      return bitField0_ == other.bitField0_
        && (!hasBeginTime() || beginTime == other.beginTime)
        && (!hasEndTime() || endTime == other.endTime)
        && (!hasLimitLevel() || limitLevel == other.limitLevel)
        && (!hasBanType() || banType == other.banType);
    }

    @Override
    public void writeTo(final ProtoSink output) throws IOException {
      if ((bitField0_ & 0x00000001) != 0) {
        output.writeRawByte((byte) 8);
        output.writeInt64NoTag(beginTime);
      }
      if ((bitField0_ & 0x00000002) != 0) {
        output.writeRawByte((byte) 16);
        output.writeInt64NoTag(endTime);
      }
      if ((bitField0_ & 0x00000004) != 0) {
        output.writeRawByte((byte) 24);
        output.writeUInt32NoTag(limitLevel);
      }
      if ((bitField0_ & 0x00000008) != 0) {
        output.writeRawByte((byte) 32);
        output.writeUInt32NoTag(banType);
      }
    }

    @Override
    protected int computeSerializedSize() {
      int size = 0;
      if ((bitField0_ & 0x00000001) != 0) {
        size += 1 + ProtoSink.computeInt64SizeNoTag(beginTime);
      }
      if ((bitField0_ & 0x00000002) != 0) {
        size += 1 + ProtoSink.computeInt64SizeNoTag(endTime);
      }
      if ((bitField0_ & 0x00000004) != 0) {
        size += 1 + ProtoSink.computeUInt32SizeNoTag(limitLevel);
      }
      if ((bitField0_ & 0x00000008) != 0) {
        size += 1 + ProtoSink.computeUInt32SizeNoTag(banType);
      }
      return size;
    }

    @Override
    @SuppressWarnings("fallthrough")
    public BlackInfo mergeFrom(final ProtoSource input) throws IOException {
      // Enabled Fall-Through Optimization (QuickBuffers)
      int tag = input.readTag();
      while (true) {
        switch (tag) {
          case 8: {
            // beginTime
            beginTime = input.readInt64();
            bitField0_ |= 0x00000001;
            tag = input.readTag();
            if (tag != 16) {
              break;
            }
          }
          case 16: {
            // endTime
            endTime = input.readInt64();
            bitField0_ |= 0x00000002;
            tag = input.readTag();
            if (tag != 24) {
              break;
            }
          }
          case 24: {
            // limitLevel
            limitLevel = input.readUInt32();
            bitField0_ |= 0x00000004;
            tag = input.readTag();
            if (tag != 32) {
              break;
            }
          }
          case 32: {
            // banType
            banType = input.readUInt32();
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
        output.writeInt64(FieldNames.beginTime, beginTime);
      }
      if ((bitField0_ & 0x00000002) != 0) {
        output.writeInt64(FieldNames.endTime, endTime);
      }
      if ((bitField0_ & 0x00000004) != 0) {
        output.writeUInt32(FieldNames.limitLevel, limitLevel);
      }
      if ((bitField0_ & 0x00000008) != 0) {
        output.writeUInt32(FieldNames.banType, banType);
      }
      output.endObject();
    }

    @Override
    public BlackInfo mergeFrom(final JsonSource input) throws IOException {
      if (!input.beginObject()) {
        return this;
      }
      while (!input.isAtEnd()) {
        switch (input.readFieldHash()) {
          case -1072839914:
          case 1112183971: {
            if (input.isAtField(FieldNames.beginTime)) {
              if (!input.trySkipNullValue()) {
                beginTime = input.readInt64();
                bitField0_ |= 0x00000001;
              }
            } else {
              input.skipUnknownField();
            }
            break;
          }
          case -1607243192:
          case 1725551537: {
            if (input.isAtField(FieldNames.endTime)) {
              if (!input.trySkipNullValue()) {
                endTime = input.readInt64();
                bitField0_ |= 0x00000002;
              }
            } else {
              input.skipUnknownField();
            }
            break;
          }
          case -1767080823:
          case 1604997632: {
            if (input.isAtField(FieldNames.limitLevel)) {
              if (!input.trySkipNullValue()) {
                limitLevel = input.readUInt32();
                bitField0_ |= 0x00000004;
              }
            } else {
              input.skipUnknownField();
            }
            break;
          }
          case -337715223:
          case -1869218454: {
            if (input.isAtField(FieldNames.banType)) {
              if (!input.trySkipNullValue()) {
                banType = input.readUInt32();
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
    public BlackInfo clone() {
      return new BlackInfo().copyFrom(this);
    }

    @Override
    public boolean isEmpty() {
      return ((bitField0_) == 0);
    }

    public static BlackInfo parseFrom(final byte[] data) throws InvalidProtocolBufferException {
      return ProtoMessage.mergeFrom(new BlackInfo(), data).checkInitialized();
    }

    public static BlackInfo parseFrom(final ProtoSource input) throws IOException {
      return ProtoMessage.mergeFrom(new BlackInfo(), input).checkInitialized();
    }

    public static BlackInfo parseFrom(final JsonSource input) throws IOException {
      return ProtoMessage.mergeFrom(new BlackInfo(), input).checkInitialized();
    }

    /**
     * @return factory for creating BlackInfo messages
     */
    public static MessageFactory<BlackInfo> getFactory() {
      return BlackInfoFactory.INSTANCE;
    }

    private enum BlackInfoFactory implements MessageFactory<BlackInfo> {
      INSTANCE;

      @Override
      public BlackInfo create() {
        return BlackInfo.newInstance();
      }
    }

    /**
     * Contains name constants used for serializing JSON
     */
    static class FieldNames {
      static final FieldName beginTime = FieldName.forField("beginTime", "begin_time");

      static final FieldName endTime = FieldName.forField("endTime", "end_time");

      static final FieldName limitLevel = FieldName.forField("limitLevel", "limit_level");

      static final FieldName banType = FieldName.forField("banType", "ban_type");
    }
  }
}
