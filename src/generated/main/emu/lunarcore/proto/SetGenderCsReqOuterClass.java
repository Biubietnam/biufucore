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

public final class SetGenderCsReqOuterClass {
  /**
   * Protobuf type {@code SetGenderCsReq}
   */
  public static final class SetGenderCsReq extends ProtoMessage<SetGenderCsReq> implements Cloneable {
    private static final long serialVersionUID = 0L;

    /**
     * <code>optional .Gender GLBIOLFDHOL = 15;</code>
     */
    private int gLBIOLFDHOL;

    private SetGenderCsReq() {
    }

    /**
     * @return a new empty instance of {@code SetGenderCsReq}
     */
    public static SetGenderCsReq newInstance() {
      return new SetGenderCsReq();
    }

    /**
     * <code>optional .Gender GLBIOLFDHOL = 15;</code>
     * @return whether the gLBIOLFDHOL field is set
     */
    public boolean hasGLBIOLFDHOL() {
      return (bitField0_ & 0x00000001) != 0;
    }

    /**
     * <code>optional .Gender GLBIOLFDHOL = 15;</code>
     * @return this
     */
    public SetGenderCsReq clearGLBIOLFDHOL() {
      bitField0_ &= ~0x00000001;
      gLBIOLFDHOL = 0;
      return this;
    }

    /**
     * <code>optional .Gender GLBIOLFDHOL = 15;</code>
     * @return the gLBIOLFDHOL
     */
    public GenderOuterClass.Gender getGLBIOLFDHOL() {
      return GenderOuterClass.Gender.forNumber(gLBIOLFDHOL);
    }

    /**
     * Gets the value of the internal enum store. The result is
     * equivalent to {@link SetGenderCsReq#getGLBIOLFDHOL()}.getNumber().
     *
     * @return numeric wire representation
     */
    public int getGLBIOLFDHOLValue() {
      return gLBIOLFDHOL;
    }

    /**
     * Sets the value of the internal enum store. This does not
     * do any validity checks, so be sure to use appropriate value
     * constants from {@link GenderOuterClass.Gender}. Setting an invalid value
     * can cause {@link SetGenderCsReq#getGLBIOLFDHOL()} to return null
     *
     * @param value the numeric wire value to set
     * @return this
     */
    public SetGenderCsReq setGLBIOLFDHOLValue(final int value) {
      bitField0_ |= 0x00000001;
      gLBIOLFDHOL = value;
      return this;
    }

    /**
     * <code>optional .Gender GLBIOLFDHOL = 15;</code>
     * @param value the gLBIOLFDHOL to set
     * @return this
     */
    public SetGenderCsReq setGLBIOLFDHOL(final GenderOuterClass.Gender value) {
      bitField0_ |= 0x00000001;
      gLBIOLFDHOL = value.getNumber();
      return this;
    }

    @Override
    public SetGenderCsReq copyFrom(final SetGenderCsReq other) {
      cachedSize = other.cachedSize;
      if ((bitField0_ | other.bitField0_) != 0) {
        bitField0_ = other.bitField0_;
        gLBIOLFDHOL = other.gLBIOLFDHOL;
      }
      return this;
    }

    @Override
    public SetGenderCsReq mergeFrom(final SetGenderCsReq other) {
      if (other.isEmpty()) {
        return this;
      }
      cachedSize = -1;
      if (other.hasGLBIOLFDHOL()) {
        setGLBIOLFDHOLValue(other.gLBIOLFDHOL);
      }
      return this;
    }

    @Override
    public SetGenderCsReq clear() {
      if (isEmpty()) {
        return this;
      }
      cachedSize = -1;
      bitField0_ = 0;
      gLBIOLFDHOL = 0;
      return this;
    }

    @Override
    public SetGenderCsReq clearQuick() {
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
      if (!(o instanceof SetGenderCsReq)) {
        return false;
      }
      SetGenderCsReq other = (SetGenderCsReq) o;
      return bitField0_ == other.bitField0_
        && (!hasGLBIOLFDHOL() || gLBIOLFDHOL == other.gLBIOLFDHOL);
    }

    @Override
    public void writeTo(final ProtoSink output) throws IOException {
      if ((bitField0_ & 0x00000001) != 0) {
        output.writeRawByte((byte) 120);
        output.writeEnumNoTag(gLBIOLFDHOL);
      }
    }

    @Override
    protected int computeSerializedSize() {
      int size = 0;
      if ((bitField0_ & 0x00000001) != 0) {
        size += 1 + ProtoSink.computeEnumSizeNoTag(gLBIOLFDHOL);
      }
      return size;
    }

    @Override
    @SuppressWarnings("fallthrough")
    public SetGenderCsReq mergeFrom(final ProtoSource input) throws IOException {
      // Enabled Fall-Through Optimization (QuickBuffers)
      int tag = input.readTag();
      while (true) {
        switch (tag) {
          case 120: {
            // gLBIOLFDHOL
            final int value = input.readInt32();
            if (GenderOuterClass.Gender.forNumber(value) != null) {
              gLBIOLFDHOL = value;
              bitField0_ |= 0x00000001;
            }
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
        output.writeEnum(FieldNames.gLBIOLFDHOL, gLBIOLFDHOL, GenderOuterClass.Gender.converter());
      }
      output.endObject();
    }

    @Override
    public SetGenderCsReq mergeFrom(final JsonSource input) throws IOException {
      if (!input.beginObject()) {
        return this;
      }
      while (!input.isAtEnd()) {
        switch (input.readFieldHash()) {
          case -2100520578: {
            if (input.isAtField(FieldNames.gLBIOLFDHOL)) {
              if (!input.trySkipNullValue()) {
                final GenderOuterClass.Gender value = input.readEnum(GenderOuterClass.Gender.converter());
                if (value != null) {
                  gLBIOLFDHOL = value.getNumber();
                  bitField0_ |= 0x00000001;
                } else {
                  input.skipUnknownEnumValue();
                }
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
    public SetGenderCsReq clone() {
      return new SetGenderCsReq().copyFrom(this);
    }

    @Override
    public boolean isEmpty() {
      return ((bitField0_) == 0);
    }

    public static SetGenderCsReq parseFrom(final byte[] data) throws
        InvalidProtocolBufferException {
      return ProtoMessage.mergeFrom(new SetGenderCsReq(), data).checkInitialized();
    }

    public static SetGenderCsReq parseFrom(final ProtoSource input) throws IOException {
      return ProtoMessage.mergeFrom(new SetGenderCsReq(), input).checkInitialized();
    }

    public static SetGenderCsReq parseFrom(final JsonSource input) throws IOException {
      return ProtoMessage.mergeFrom(new SetGenderCsReq(), input).checkInitialized();
    }

    /**
     * @return factory for creating SetGenderCsReq messages
     */
    public static MessageFactory<SetGenderCsReq> getFactory() {
      return SetGenderCsReqFactory.INSTANCE;
    }

    private enum SetGenderCsReqFactory implements MessageFactory<SetGenderCsReq> {
      INSTANCE;

      @Override
      public SetGenderCsReq create() {
        return SetGenderCsReq.newInstance();
      }
    }

    /**
     * Contains name constants used for serializing JSON
     */
    static class FieldNames {
      static final FieldName gLBIOLFDHOL = FieldName.forField("GLBIOLFDHOL");
    }
  }
}
