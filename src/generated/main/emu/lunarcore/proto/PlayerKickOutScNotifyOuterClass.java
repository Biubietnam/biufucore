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

public final class PlayerKickOutScNotifyOuterClass {
  /**
   * Protobuf type {@code PlayerKickOutScNotify}
   */
  public static final class PlayerKickOutScNotify extends ProtoMessage<PlayerKickOutScNotify> implements Cloneable {
    private static final long serialVersionUID = 0L;

    /**
     * <code>optional .KickType kick_type = 12;</code>
     */
    private int kickType;

    /**
     * <code>optional .BlackInfo black_info = 5;</code>
     */
    private final BlackInfoOuterClass.BlackInfo blackInfo = BlackInfoOuterClass.BlackInfo.newInstance();

    private PlayerKickOutScNotify() {
    }

    /**
     * @return a new empty instance of {@code PlayerKickOutScNotify}
     */
    public static PlayerKickOutScNotify newInstance() {
      return new PlayerKickOutScNotify();
    }

    public boolean hasKickInfo() {
      return (((bitField0_ & 0x00000003)) != 0);
    }

    public PlayerKickOutScNotify clearKickInfo() {
      if (hasKickInfo()) {
        clearKickType();
        clearBlackInfo();
      }
      return this;
    }

    private void clearKickInfoOtherKickType() {
      if ((((bitField0_ & 0x00000002)) != 0)) {
        clearBlackInfo();
      }
    }

    private void clearKickInfoOtherBlackInfo() {
      if ((((bitField0_ & 0x00000001)) != 0)) {
        clearKickType();
      }
    }

    /**
     * <code>optional .KickType kick_type = 12;</code>
     * @return whether the kickType field is set
     */
    public boolean hasKickType() {
      return (bitField0_ & 0x00000001) != 0;
    }

    /**
     * <code>optional .KickType kick_type = 12;</code>
     * @return this
     */
    public PlayerKickOutScNotify clearKickType() {
      bitField0_ &= ~0x00000001;
      kickType = 0;
      return this;
    }

    /**
     * <code>optional .KickType kick_type = 12;</code>
     * @return the kickType
     */
    public KickTypeOuterClass.KickType getKickType() {
      return KickTypeOuterClass.KickType.forNumber(kickType);
    }

    /**
     * Gets the value of the internal enum store. The result is
     * equivalent to {@link PlayerKickOutScNotify#getKickType()}.getNumber().
     *
     * @return numeric wire representation
     */
    public int getKickTypeValue() {
      return kickType;
    }

    /**
     * Sets the value of the internal enum store. This does not
     * do any validity checks, so be sure to use appropriate value
     * constants from {@link KickTypeOuterClass.KickType}. Setting an invalid value
     * can cause {@link PlayerKickOutScNotify#getKickType()} to return null
     *
     * @param value the numeric wire value to set
     * @return this
     */
    public PlayerKickOutScNotify setKickTypeValue(final int value) {
      bitField0_ |= 0x00000001;
      kickType = value;
      return this;
    }

    /**
     * <code>optional .KickType kick_type = 12;</code>
     * @param value the kickType to set
     * @return this
     */
    public PlayerKickOutScNotify setKickType(final KickTypeOuterClass.KickType value) {
      clearKickInfoOtherKickType();
      bitField0_ |= 0x00000001;
      kickType = value.getNumber();
      return this;
    }

    /**
     * <code>optional .BlackInfo black_info = 5;</code>
     * @return whether the blackInfo field is set
     */
    public boolean hasBlackInfo() {
      return (bitField0_ & 0x00000002) != 0;
    }

    /**
     * <code>optional .BlackInfo black_info = 5;</code>
     * @return this
     */
    public PlayerKickOutScNotify clearBlackInfo() {
      bitField0_ &= ~0x00000002;
      blackInfo.clear();
      return this;
    }

    /**
     * <code>optional .BlackInfo black_info = 5;</code>
     *
     * This method returns the internal storage object without modifying any has state.
     * The returned object should not be modified and be treated as read-only.
     *
     * Use {@link #getMutableBlackInfo()} if you want to modify it.
     *
     * @return internal storage object for reading
     */
    public BlackInfoOuterClass.BlackInfo getBlackInfo() {
      return blackInfo;
    }

    /**
     * <code>optional .BlackInfo black_info = 5;</code>
     *
     * This method returns the internal storage object and sets the corresponding
     * has state. The returned object will become part of this message and its
     * contents may be modified as long as the has state is not cleared.
     *
     * @return internal storage object for modifications
     */
    public BlackInfoOuterClass.BlackInfo getMutableBlackInfo() {
      clearKickInfoOtherBlackInfo();
      bitField0_ |= 0x00000002;
      return blackInfo;
    }

    /**
     * <code>optional .BlackInfo black_info = 5;</code>
     * @param value the blackInfo to set
     * @return this
     */
    public PlayerKickOutScNotify setBlackInfo(final BlackInfoOuterClass.BlackInfo value) {
      clearKickInfoOtherBlackInfo();
      bitField0_ |= 0x00000002;
      blackInfo.copyFrom(value);
      return this;
    }

    @Override
    public PlayerKickOutScNotify copyFrom(final PlayerKickOutScNotify other) {
      cachedSize = other.cachedSize;
      if ((bitField0_ | other.bitField0_) != 0) {
        bitField0_ = other.bitField0_;
        kickType = other.kickType;
        blackInfo.copyFrom(other.blackInfo);
      }
      return this;
    }

    @Override
    public PlayerKickOutScNotify mergeFrom(final PlayerKickOutScNotify other) {
      if (other.isEmpty()) {
        return this;
      }
      cachedSize = -1;
      if (other.hasKickType()) {
        setKickTypeValue(other.kickType);
      }
      if (other.hasBlackInfo()) {
        getMutableBlackInfo().mergeFrom(other.blackInfo);
      }
      return this;
    }

    @Override
    public PlayerKickOutScNotify clear() {
      if (isEmpty()) {
        return this;
      }
      cachedSize = -1;
      bitField0_ = 0;
      kickType = 0;
      blackInfo.clear();
      return this;
    }

    @Override
    public PlayerKickOutScNotify clearQuick() {
      if (isEmpty()) {
        return this;
      }
      cachedSize = -1;
      bitField0_ = 0;
      blackInfo.clearQuick();
      return this;
    }

    @Override
    public boolean equals(Object o) {
      if (o == this) {
        return true;
      }
      if (!(o instanceof PlayerKickOutScNotify)) {
        return false;
      }
      PlayerKickOutScNotify other = (PlayerKickOutScNotify) o;
      return bitField0_ == other.bitField0_
        && (!hasKickType() || kickType == other.kickType)
        && (!hasBlackInfo() || blackInfo.equals(other.blackInfo));
    }

    @Override
    public void writeTo(final ProtoSink output) throws IOException {
      if ((bitField0_ & 0x00000001) != 0) {
        output.writeRawByte((byte) 96);
        output.writeEnumNoTag(kickType);
      }
      if ((bitField0_ & 0x00000002) != 0) {
        output.writeRawByte((byte) 42);
        output.writeMessageNoTag(blackInfo);
      }
    }

    @Override
    protected int computeSerializedSize() {
      int size = 0;
      if ((bitField0_ & 0x00000001) != 0) {
        size += 1 + ProtoSink.computeEnumSizeNoTag(kickType);
      }
      if ((bitField0_ & 0x00000002) != 0) {
        size += 1 + ProtoSink.computeMessageSizeNoTag(blackInfo);
      }
      return size;
    }

    @Override
    @SuppressWarnings("fallthrough")
    public PlayerKickOutScNotify mergeFrom(final ProtoSource input) throws IOException {
      // Enabled Fall-Through Optimization (QuickBuffers)
      int tag = input.readTag();
      while (true) {
        switch (tag) {
          case 96: {
            // kickType
            clearKickInfoOtherKickType();
            final int value = input.readInt32();
            if (KickTypeOuterClass.KickType.forNumber(value) != null) {
              kickType = value;
              bitField0_ |= 0x00000001;
            }
            tag = input.readTag();
            if (tag != 42) {
              break;
            }
          }
          case 42: {
            // blackInfo
            clearKickInfoOtherBlackInfo();
            input.readMessage(blackInfo);
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
        output.writeEnum(FieldNames.kickType, kickType, KickTypeOuterClass.KickType.converter());
      }
      if ((bitField0_ & 0x00000002) != 0) {
        output.writeMessage(FieldNames.blackInfo, blackInfo);
      }
      output.endObject();
    }

    @Override
    public PlayerKickOutScNotify mergeFrom(final JsonSource input) throws IOException {
      if (!input.beginObject()) {
        return this;
      }
      while (!input.isAtEnd()) {
        switch (input.readFieldHash()) {
          case -863524192:
          case -989427309: {
            if (input.isAtField(FieldNames.kickType)) {
              if (!input.trySkipNullValue()) {
                clearKickInfoOtherKickType();
                final KickTypeOuterClass.KickType value = input.readEnum(KickTypeOuterClass.KickType.converter());
                if (value != null) {
                  kickType = value.getNumber();
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
          case 1331974477:
          case -1638288146: {
            if (input.isAtField(FieldNames.blackInfo)) {
              if (!input.trySkipNullValue()) {
                clearKickInfoOtherBlackInfo();
                input.readMessage(blackInfo);
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
    public PlayerKickOutScNotify clone() {
      return new PlayerKickOutScNotify().copyFrom(this);
    }

    @Override
    public boolean isEmpty() {
      return ((bitField0_) == 0);
    }

    public static PlayerKickOutScNotify parseFrom(final byte[] data) throws
        InvalidProtocolBufferException {
      return ProtoMessage.mergeFrom(new PlayerKickOutScNotify(), data).checkInitialized();
    }

    public static PlayerKickOutScNotify parseFrom(final ProtoSource input) throws IOException {
      return ProtoMessage.mergeFrom(new PlayerKickOutScNotify(), input).checkInitialized();
    }

    public static PlayerKickOutScNotify parseFrom(final JsonSource input) throws IOException {
      return ProtoMessage.mergeFrom(new PlayerKickOutScNotify(), input).checkInitialized();
    }

    /**
     * @return factory for creating PlayerKickOutScNotify messages
     */
    public static MessageFactory<PlayerKickOutScNotify> getFactory() {
      return PlayerKickOutScNotifyFactory.INSTANCE;
    }

    private enum PlayerKickOutScNotifyFactory implements MessageFactory<PlayerKickOutScNotify> {
      INSTANCE;

      @Override
      public PlayerKickOutScNotify create() {
        return PlayerKickOutScNotify.newInstance();
      }
    }

    /**
     * Contains name constants used for serializing JSON
     */
    static class FieldNames {
      static final FieldName kickType = FieldName.forField("kickType", "kick_type");

      static final FieldName blackInfo = FieldName.forField("blackInfo", "black_info");
    }
  }
}