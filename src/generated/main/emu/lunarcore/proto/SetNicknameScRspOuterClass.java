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

public final class SetNicknameScRspOuterClass {
  /**
   * Protobuf type {@code SetNicknameScRsp}
   */
  public static final class SetNicknameScRsp extends ProtoMessage<SetNicknameScRsp> implements Cloneable {
    private static final long serialVersionUID = 0L;

    /**
     * <code>optional int64 PGCICECKJDP = 11;</code>
     */
    private long pGCICECKJDP;

    /**
     * <code>optional uint32 retcode = 9;</code>
     */
    private int retcode;

    /**
     * <code>optional bool is_modify = 6;</code>
     */
    private boolean isModify;

    private SetNicknameScRsp() {
    }

    /**
     * @return a new empty instance of {@code SetNicknameScRsp}
     */
    public static SetNicknameScRsp newInstance() {
      return new SetNicknameScRsp();
    }

    /**
     * <code>optional int64 PGCICECKJDP = 11;</code>
     * @return whether the pGCICECKJDP field is set
     */
    public boolean hasPGCICECKJDP() {
      return (bitField0_ & 0x00000001) != 0;
    }

    /**
     * <code>optional int64 PGCICECKJDP = 11;</code>
     * @return this
     */
    public SetNicknameScRsp clearPGCICECKJDP() {
      bitField0_ &= ~0x00000001;
      pGCICECKJDP = 0L;
      return this;
    }

    /**
     * <code>optional int64 PGCICECKJDP = 11;</code>
     * @return the pGCICECKJDP
     */
    public long getPGCICECKJDP() {
      return pGCICECKJDP;
    }

    /**
     * <code>optional int64 PGCICECKJDP = 11;</code>
     * @param value the pGCICECKJDP to set
     * @return this
     */
    public SetNicknameScRsp setPGCICECKJDP(final long value) {
      bitField0_ |= 0x00000001;
      pGCICECKJDP = value;
      return this;
    }

    /**
     * <code>optional uint32 retcode = 9;</code>
     * @return whether the retcode field is set
     */
    public boolean hasRetcode() {
      return (bitField0_ & 0x00000002) != 0;
    }

    /**
     * <code>optional uint32 retcode = 9;</code>
     * @return this
     */
    public SetNicknameScRsp clearRetcode() {
      bitField0_ &= ~0x00000002;
      retcode = 0;
      return this;
    }

    /**
     * <code>optional uint32 retcode = 9;</code>
     * @return the retcode
     */
    public int getRetcode() {
      return retcode;
    }

    /**
     * <code>optional uint32 retcode = 9;</code>
     * @param value the retcode to set
     * @return this
     */
    public SetNicknameScRsp setRetcode(final int value) {
      bitField0_ |= 0x00000002;
      retcode = value;
      return this;
    }

    /**
     * <code>optional bool is_modify = 6;</code>
     * @return whether the isModify field is set
     */
    public boolean hasIsModify() {
      return (bitField0_ & 0x00000004) != 0;
    }

    /**
     * <code>optional bool is_modify = 6;</code>
     * @return this
     */
    public SetNicknameScRsp clearIsModify() {
      bitField0_ &= ~0x00000004;
      isModify = false;
      return this;
    }

    /**
     * <code>optional bool is_modify = 6;</code>
     * @return the isModify
     */
    public boolean getIsModify() {
      return isModify;
    }

    /**
     * <code>optional bool is_modify = 6;</code>
     * @param value the isModify to set
     * @return this
     */
    public SetNicknameScRsp setIsModify(final boolean value) {
      bitField0_ |= 0x00000004;
      isModify = value;
      return this;
    }

    @Override
    public SetNicknameScRsp copyFrom(final SetNicknameScRsp other) {
      cachedSize = other.cachedSize;
      if ((bitField0_ | other.bitField0_) != 0) {
        bitField0_ = other.bitField0_;
        pGCICECKJDP = other.pGCICECKJDP;
        retcode = other.retcode;
        isModify = other.isModify;
      }
      return this;
    }

    @Override
    public SetNicknameScRsp mergeFrom(final SetNicknameScRsp other) {
      if (other.isEmpty()) {
        return this;
      }
      cachedSize = -1;
      if (other.hasPGCICECKJDP()) {
        setPGCICECKJDP(other.pGCICECKJDP);
      }
      if (other.hasRetcode()) {
        setRetcode(other.retcode);
      }
      if (other.hasIsModify()) {
        setIsModify(other.isModify);
      }
      return this;
    }

    @Override
    public SetNicknameScRsp clear() {
      if (isEmpty()) {
        return this;
      }
      cachedSize = -1;
      bitField0_ = 0;
      pGCICECKJDP = 0L;
      retcode = 0;
      isModify = false;
      return this;
    }

    @Override
    public SetNicknameScRsp clearQuick() {
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
      if (!(o instanceof SetNicknameScRsp)) {
        return false;
      }
      SetNicknameScRsp other = (SetNicknameScRsp) o;
      return bitField0_ == other.bitField0_
        && (!hasPGCICECKJDP() || pGCICECKJDP == other.pGCICECKJDP)
        && (!hasRetcode() || retcode == other.retcode)
        && (!hasIsModify() || isModify == other.isModify);
    }

    @Override
    public void writeTo(final ProtoSink output) throws IOException {
      if ((bitField0_ & 0x00000001) != 0) {
        output.writeRawByte((byte) 88);
        output.writeInt64NoTag(pGCICECKJDP);
      }
      if ((bitField0_ & 0x00000002) != 0) {
        output.writeRawByte((byte) 72);
        output.writeUInt32NoTag(retcode);
      }
      if ((bitField0_ & 0x00000004) != 0) {
        output.writeRawByte((byte) 48);
        output.writeBoolNoTag(isModify);
      }
    }

    @Override
    protected int computeSerializedSize() {
      int size = 0;
      if ((bitField0_ & 0x00000001) != 0) {
        size += 1 + ProtoSink.computeInt64SizeNoTag(pGCICECKJDP);
      }
      if ((bitField0_ & 0x00000002) != 0) {
        size += 1 + ProtoSink.computeUInt32SizeNoTag(retcode);
      }
      if ((bitField0_ & 0x00000004) != 0) {
        size += 2;
      }
      return size;
    }

    @Override
    @SuppressWarnings("fallthrough")
    public SetNicknameScRsp mergeFrom(final ProtoSource input) throws IOException {
      // Enabled Fall-Through Optimization (QuickBuffers)
      int tag = input.readTag();
      while (true) {
        switch (tag) {
          case 88: {
            // pGCICECKJDP
            pGCICECKJDP = input.readInt64();
            bitField0_ |= 0x00000001;
            tag = input.readTag();
            if (tag != 72) {
              break;
            }
          }
          case 72: {
            // retcode
            retcode = input.readUInt32();
            bitField0_ |= 0x00000002;
            tag = input.readTag();
            if (tag != 48) {
              break;
            }
          }
          case 48: {
            // isModify
            isModify = input.readBool();
            bitField0_ |= 0x00000004;
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
        output.writeInt64(FieldNames.pGCICECKJDP, pGCICECKJDP);
      }
      if ((bitField0_ & 0x00000002) != 0) {
        output.writeUInt32(FieldNames.retcode, retcode);
      }
      if ((bitField0_ & 0x00000004) != 0) {
        output.writeBool(FieldNames.isModify, isModify);
      }
      output.endObject();
    }

    @Override
    public SetNicknameScRsp mergeFrom(final JsonSource input) throws IOException {
      if (!input.beginObject()) {
        return this;
      }
      while (!input.isAtEnd()) {
        switch (input.readFieldHash()) {
          case 113792655: {
            if (input.isAtField(FieldNames.pGCICECKJDP)) {
              if (!input.trySkipNullValue()) {
                pGCICECKJDP = input.readInt64();
                bitField0_ |= 0x00000001;
              }
            } else {
              input.skipUnknownField();
            }
            break;
          }
          case 1097936398: {
            if (input.isAtField(FieldNames.retcode)) {
              if (!input.trySkipNullValue()) {
                retcode = input.readUInt32();
                bitField0_ |= 0x00000002;
              }
            } else {
              input.skipUnknownField();
            }
            break;
          }
          case -394761596:
          case -604756625: {
            if (input.isAtField(FieldNames.isModify)) {
              if (!input.trySkipNullValue()) {
                isModify = input.readBool();
                bitField0_ |= 0x00000004;
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
    public SetNicknameScRsp clone() {
      return new SetNicknameScRsp().copyFrom(this);
    }

    @Override
    public boolean isEmpty() {
      return ((bitField0_) == 0);
    }

    public static SetNicknameScRsp parseFrom(final byte[] data) throws
        InvalidProtocolBufferException {
      return ProtoMessage.mergeFrom(new SetNicknameScRsp(), data).checkInitialized();
    }

    public static SetNicknameScRsp parseFrom(final ProtoSource input) throws IOException {
      return ProtoMessage.mergeFrom(new SetNicknameScRsp(), input).checkInitialized();
    }

    public static SetNicknameScRsp parseFrom(final JsonSource input) throws IOException {
      return ProtoMessage.mergeFrom(new SetNicknameScRsp(), input).checkInitialized();
    }

    /**
     * @return factory for creating SetNicknameScRsp messages
     */
    public static MessageFactory<SetNicknameScRsp> getFactory() {
      return SetNicknameScRspFactory.INSTANCE;
    }

    private enum SetNicknameScRspFactory implements MessageFactory<SetNicknameScRsp> {
      INSTANCE;

      @Override
      public SetNicknameScRsp create() {
        return SetNicknameScRsp.newInstance();
      }
    }

    /**
     * Contains name constants used for serializing JSON
     */
    static class FieldNames {
      static final FieldName pGCICECKJDP = FieldName.forField("PGCICECKJDP");

      static final FieldName retcode = FieldName.forField("retcode");

      static final FieldName isModify = FieldName.forField("isModify", "is_modify");
    }
  }
}
