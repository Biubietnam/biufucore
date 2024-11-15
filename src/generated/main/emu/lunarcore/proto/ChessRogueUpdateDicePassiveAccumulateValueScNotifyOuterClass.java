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

public final class ChessRogueUpdateDicePassiveAccumulateValueScNotifyOuterClass {
  /**
   * Protobuf type {@code ChessRogueUpdateDicePassiveAccumulateValueScNotify}
   */
  public static final class ChessRogueUpdateDicePassiveAccumulateValueScNotify extends ProtoMessage<ChessRogueUpdateDicePassiveAccumulateValueScNotify> implements Cloneable {
    private static final long serialVersionUID = 0L;

    /**
     * <code>optional int32 BFNDFONMNKI = 5;</code>
     */
    private int bFNDFONMNKI;

    private ChessRogueUpdateDicePassiveAccumulateValueScNotify() {
    }

    /**
     * @return a new empty instance of {@code ChessRogueUpdateDicePassiveAccumulateValueScNotify}
     */
    public static ChessRogueUpdateDicePassiveAccumulateValueScNotify newInstance() {
      return new ChessRogueUpdateDicePassiveAccumulateValueScNotify();
    }

    /**
     * <code>optional int32 BFNDFONMNKI = 5;</code>
     * @return whether the bFNDFONMNKI field is set
     */
    public boolean hasBFNDFONMNKI() {
      return (bitField0_ & 0x00000001) != 0;
    }

    /**
     * <code>optional int32 BFNDFONMNKI = 5;</code>
     * @return this
     */
    public ChessRogueUpdateDicePassiveAccumulateValueScNotify clearBFNDFONMNKI() {
      bitField0_ &= ~0x00000001;
      bFNDFONMNKI = 0;
      return this;
    }

    /**
     * <code>optional int32 BFNDFONMNKI = 5;</code>
     * @return the bFNDFONMNKI
     */
    public int getBFNDFONMNKI() {
      return bFNDFONMNKI;
    }

    /**
     * <code>optional int32 BFNDFONMNKI = 5;</code>
     * @param value the bFNDFONMNKI to set
     * @return this
     */
    public ChessRogueUpdateDicePassiveAccumulateValueScNotify setBFNDFONMNKI(final int value) {
      bitField0_ |= 0x00000001;
      bFNDFONMNKI = value;
      return this;
    }

    @Override
    public ChessRogueUpdateDicePassiveAccumulateValueScNotify copyFrom(
        final ChessRogueUpdateDicePassiveAccumulateValueScNotify other) {
      cachedSize = other.cachedSize;
      if ((bitField0_ | other.bitField0_) != 0) {
        bitField0_ = other.bitField0_;
        bFNDFONMNKI = other.bFNDFONMNKI;
      }
      return this;
    }

    @Override
    public ChessRogueUpdateDicePassiveAccumulateValueScNotify mergeFrom(
        final ChessRogueUpdateDicePassiveAccumulateValueScNotify other) {
      if (other.isEmpty()) {
        return this;
      }
      cachedSize = -1;
      if (other.hasBFNDFONMNKI()) {
        setBFNDFONMNKI(other.bFNDFONMNKI);
      }
      return this;
    }

    @Override
    public ChessRogueUpdateDicePassiveAccumulateValueScNotify clear() {
      if (isEmpty()) {
        return this;
      }
      cachedSize = -1;
      bitField0_ = 0;
      bFNDFONMNKI = 0;
      return this;
    }

    @Override
    public ChessRogueUpdateDicePassiveAccumulateValueScNotify clearQuick() {
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
      if (!(o instanceof ChessRogueUpdateDicePassiveAccumulateValueScNotify)) {
        return false;
      }
      ChessRogueUpdateDicePassiveAccumulateValueScNotify other = (ChessRogueUpdateDicePassiveAccumulateValueScNotify) o;
      return bitField0_ == other.bitField0_
        && (!hasBFNDFONMNKI() || bFNDFONMNKI == other.bFNDFONMNKI);
    }

    @Override
    public void writeTo(final ProtoSink output) throws IOException {
      if ((bitField0_ & 0x00000001) != 0) {
        output.writeRawByte((byte) 40);
        output.writeInt32NoTag(bFNDFONMNKI);
      }
    }

    @Override
    protected int computeSerializedSize() {
      int size = 0;
      if ((bitField0_ & 0x00000001) != 0) {
        size += 1 + ProtoSink.computeInt32SizeNoTag(bFNDFONMNKI);
      }
      return size;
    }

    @Override
    @SuppressWarnings("fallthrough")
    public ChessRogueUpdateDicePassiveAccumulateValueScNotify mergeFrom(final ProtoSource input)
        throws IOException {
      // Enabled Fall-Through Optimization (QuickBuffers)
      int tag = input.readTag();
      while (true) {
        switch (tag) {
          case 40: {
            // bFNDFONMNKI
            bFNDFONMNKI = input.readInt32();
            bitField0_ |= 0x00000001;
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
        output.writeInt32(FieldNames.bFNDFONMNKI, bFNDFONMNKI);
      }
      output.endObject();
    }

    @Override
    public ChessRogueUpdateDicePassiveAccumulateValueScNotify mergeFrom(final JsonSource input)
        throws IOException {
      if (!input.beginObject()) {
        return this;
      }
      while (!input.isAtEnd()) {
        switch (input.readFieldHash()) {
          case -169400662: {
            if (input.isAtField(FieldNames.bFNDFONMNKI)) {
              if (!input.trySkipNullValue()) {
                bFNDFONMNKI = input.readInt32();
                bitField0_ |= 0x00000001;
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
    public ChessRogueUpdateDicePassiveAccumulateValueScNotify clone() {
      return new ChessRogueUpdateDicePassiveAccumulateValueScNotify().copyFrom(this);
    }

    @Override
    public boolean isEmpty() {
      return ((bitField0_) == 0);
    }

    public static ChessRogueUpdateDicePassiveAccumulateValueScNotify parseFrom(final byte[] data)
        throws InvalidProtocolBufferException {
      return ProtoMessage.mergeFrom(new ChessRogueUpdateDicePassiveAccumulateValueScNotify(), data).checkInitialized();
    }

    public static ChessRogueUpdateDicePassiveAccumulateValueScNotify parseFrom(
        final ProtoSource input) throws IOException {
      return ProtoMessage.mergeFrom(new ChessRogueUpdateDicePassiveAccumulateValueScNotify(), input).checkInitialized();
    }

    public static ChessRogueUpdateDicePassiveAccumulateValueScNotify parseFrom(
        final JsonSource input) throws IOException {
      return ProtoMessage.mergeFrom(new ChessRogueUpdateDicePassiveAccumulateValueScNotify(), input).checkInitialized();
    }

    /**
     * @return factory for creating ChessRogueUpdateDicePassiveAccumulateValueScNotify messages
     */
    public static MessageFactory<ChessRogueUpdateDicePassiveAccumulateValueScNotify> getFactory() {
      return ChessRogueUpdateDicePassiveAccumulateValueScNotifyFactory.INSTANCE;
    }

    private enum ChessRogueUpdateDicePassiveAccumulateValueScNotifyFactory implements MessageFactory<ChessRogueUpdateDicePassiveAccumulateValueScNotify> {
      INSTANCE;

      @Override
      public ChessRogueUpdateDicePassiveAccumulateValueScNotify create() {
        return ChessRogueUpdateDicePassiveAccumulateValueScNotify.newInstance();
      }
    }

    /**
     * Contains name constants used for serializing JSON
     */
    static class FieldNames {
      static final FieldName bFNDFONMNKI = FieldName.forField("BFNDFONMNKI");
    }
  }
}
