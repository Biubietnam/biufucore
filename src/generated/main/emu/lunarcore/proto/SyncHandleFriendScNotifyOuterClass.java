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

public final class SyncHandleFriendScNotifyOuterClass {
  /**
   * <pre>
   *  DMJPOKCMEGO
   * </pre>
   *
   * Protobuf type {@code SyncHandleFriendScNotify}
   */
  public static final class SyncHandleFriendScNotify extends ProtoMessage<SyncHandleFriendScNotify> implements Cloneable {
    private static final long serialVersionUID = 0L;

    /**
     * <code>optional uint32 uid = 13;</code>
     */
    private int uid;

    /**
     * <code>optional bool handle_result = 8;</code>
     */
    private boolean handleResult;

    /**
     * <code>optional .FriendListInfo handle_friend_info = 14;</code>
     */
    private final FriendListInfoOuterClass.FriendListInfo handleFriendInfo = FriendListInfoOuterClass.FriendListInfo.newInstance();

    private SyncHandleFriendScNotify() {
    }

    /**
     * <pre>
     *  DMJPOKCMEGO
     * </pre>
     *
     * @return a new empty instance of {@code SyncHandleFriendScNotify}
     */
    public static SyncHandleFriendScNotify newInstance() {
      return new SyncHandleFriendScNotify();
    }

    /**
     * <code>optional uint32 uid = 13;</code>
     * @return whether the uid field is set
     */
    public boolean hasUid() {
      return (bitField0_ & 0x00000001) != 0;
    }

    /**
     * <code>optional uint32 uid = 13;</code>
     * @return this
     */
    public SyncHandleFriendScNotify clearUid() {
      bitField0_ &= ~0x00000001;
      uid = 0;
      return this;
    }

    /**
     * <code>optional uint32 uid = 13;</code>
     * @return the uid
     */
    public int getUid() {
      return uid;
    }

    /**
     * <code>optional uint32 uid = 13;</code>
     * @param value the uid to set
     * @return this
     */
    public SyncHandleFriendScNotify setUid(final int value) {
      bitField0_ |= 0x00000001;
      uid = value;
      return this;
    }

    /**
     * <code>optional bool handle_result = 8;</code>
     * @return whether the handleResult field is set
     */
    public boolean hasHandleResult() {
      return (bitField0_ & 0x00000002) != 0;
    }

    /**
     * <code>optional bool handle_result = 8;</code>
     * @return this
     */
    public SyncHandleFriendScNotify clearHandleResult() {
      bitField0_ &= ~0x00000002;
      handleResult = false;
      return this;
    }

    /**
     * <code>optional bool handle_result = 8;</code>
     * @return the handleResult
     */
    public boolean getHandleResult() {
      return handleResult;
    }

    /**
     * <code>optional bool handle_result = 8;</code>
     * @param value the handleResult to set
     * @return this
     */
    public SyncHandleFriendScNotify setHandleResult(final boolean value) {
      bitField0_ |= 0x00000002;
      handleResult = value;
      return this;
    }

    /**
     * <code>optional .FriendListInfo handle_friend_info = 14;</code>
     * @return whether the handleFriendInfo field is set
     */
    public boolean hasHandleFriendInfo() {
      return (bitField0_ & 0x00000004) != 0;
    }

    /**
     * <code>optional .FriendListInfo handle_friend_info = 14;</code>
     * @return this
     */
    public SyncHandleFriendScNotify clearHandleFriendInfo() {
      bitField0_ &= ~0x00000004;
      handleFriendInfo.clear();
      return this;
    }

    /**
     * <code>optional .FriendListInfo handle_friend_info = 14;</code>
     *
     * This method returns the internal storage object without modifying any has state.
     * The returned object should not be modified and be treated as read-only.
     *
     * Use {@link #getMutableHandleFriendInfo()} if you want to modify it.
     *
     * @return internal storage object for reading
     */
    public FriendListInfoOuterClass.FriendListInfo getHandleFriendInfo() {
      return handleFriendInfo;
    }

    /**
     * <code>optional .FriendListInfo handle_friend_info = 14;</code>
     *
     * This method returns the internal storage object and sets the corresponding
     * has state. The returned object will become part of this message and its
     * contents may be modified as long as the has state is not cleared.
     *
     * @return internal storage object for modifications
     */
    public FriendListInfoOuterClass.FriendListInfo getMutableHandleFriendInfo() {
      bitField0_ |= 0x00000004;
      return handleFriendInfo;
    }

    /**
     * <code>optional .FriendListInfo handle_friend_info = 14;</code>
     * @param value the handleFriendInfo to set
     * @return this
     */
    public SyncHandleFriendScNotify setHandleFriendInfo(
        final FriendListInfoOuterClass.FriendListInfo value) {
      bitField0_ |= 0x00000004;
      handleFriendInfo.copyFrom(value);
      return this;
    }

    @Override
    public SyncHandleFriendScNotify copyFrom(final SyncHandleFriendScNotify other) {
      cachedSize = other.cachedSize;
      if ((bitField0_ | other.bitField0_) != 0) {
        bitField0_ = other.bitField0_;
        uid = other.uid;
        handleResult = other.handleResult;
        handleFriendInfo.copyFrom(other.handleFriendInfo);
      }
      return this;
    }

    @Override
    public SyncHandleFriendScNotify mergeFrom(final SyncHandleFriendScNotify other) {
      if (other.isEmpty()) {
        return this;
      }
      cachedSize = -1;
      if (other.hasUid()) {
        setUid(other.uid);
      }
      if (other.hasHandleResult()) {
        setHandleResult(other.handleResult);
      }
      if (other.hasHandleFriendInfo()) {
        getMutableHandleFriendInfo().mergeFrom(other.handleFriendInfo);
      }
      return this;
    }

    @Override
    public SyncHandleFriendScNotify clear() {
      if (isEmpty()) {
        return this;
      }
      cachedSize = -1;
      bitField0_ = 0;
      uid = 0;
      handleResult = false;
      handleFriendInfo.clear();
      return this;
    }

    @Override
    public SyncHandleFriendScNotify clearQuick() {
      if (isEmpty()) {
        return this;
      }
      cachedSize = -1;
      bitField0_ = 0;
      handleFriendInfo.clearQuick();
      return this;
    }

    @Override
    public boolean equals(Object o) {
      if (o == this) {
        return true;
      }
      if (!(o instanceof SyncHandleFriendScNotify)) {
        return false;
      }
      SyncHandleFriendScNotify other = (SyncHandleFriendScNotify) o;
      return bitField0_ == other.bitField0_
        && (!hasUid() || uid == other.uid)
        && (!hasHandleResult() || handleResult == other.handleResult)
        && (!hasHandleFriendInfo() || handleFriendInfo.equals(other.handleFriendInfo));
    }

    @Override
    public void writeTo(final ProtoSink output) throws IOException {
      if ((bitField0_ & 0x00000001) != 0) {
        output.writeRawByte((byte) 104);
        output.writeUInt32NoTag(uid);
      }
      if ((bitField0_ & 0x00000002) != 0) {
        output.writeRawByte((byte) 64);
        output.writeBoolNoTag(handleResult);
      }
      if ((bitField0_ & 0x00000004) != 0) {
        output.writeRawByte((byte) 114);
        output.writeMessageNoTag(handleFriendInfo);
      }
    }

    @Override
    protected int computeSerializedSize() {
      int size = 0;
      if ((bitField0_ & 0x00000001) != 0) {
        size += 1 + ProtoSink.computeUInt32SizeNoTag(uid);
      }
      if ((bitField0_ & 0x00000002) != 0) {
        size += 2;
      }
      if ((bitField0_ & 0x00000004) != 0) {
        size += 1 + ProtoSink.computeMessageSizeNoTag(handleFriendInfo);
      }
      return size;
    }

    @Override
    @SuppressWarnings("fallthrough")
    public SyncHandleFriendScNotify mergeFrom(final ProtoSource input) throws IOException {
      // Enabled Fall-Through Optimization (QuickBuffers)
      int tag = input.readTag();
      while (true) {
        switch (tag) {
          case 104: {
            // uid
            uid = input.readUInt32();
            bitField0_ |= 0x00000001;
            tag = input.readTag();
            if (tag != 64) {
              break;
            }
          }
          case 64: {
            // handleResult
            handleResult = input.readBool();
            bitField0_ |= 0x00000002;
            tag = input.readTag();
            if (tag != 114) {
              break;
            }
          }
          case 114: {
            // handleFriendInfo
            input.readMessage(handleFriendInfo);
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
        output.writeUInt32(FieldNames.uid, uid);
      }
      if ((bitField0_ & 0x00000002) != 0) {
        output.writeBool(FieldNames.handleResult, handleResult);
      }
      if ((bitField0_ & 0x00000004) != 0) {
        output.writeMessage(FieldNames.handleFriendInfo, handleFriendInfo);
      }
      output.endObject();
    }

    @Override
    public SyncHandleFriendScNotify mergeFrom(final JsonSource input) throws IOException {
      if (!input.beginObject()) {
        return this;
      }
      while (!input.isAtEnd()) {
        switch (input.readFieldHash()) {
          case 115792: {
            if (input.isAtField(FieldNames.uid)) {
              if (!input.trySkipNullValue()) {
                uid = input.readUInt32();
                bitField0_ |= 0x00000001;
              }
            } else {
              input.skipUnknownField();
            }
            break;
          }
          case -1331436443:
          case 686987796: {
            if (input.isAtField(FieldNames.handleResult)) {
              if (!input.trySkipNullValue()) {
                handleResult = input.readBool();
                bitField0_ |= 0x00000002;
              }
            } else {
              input.skipUnknownField();
            }
            break;
          }
          case -215671628:
          case 49075736: {
            if (input.isAtField(FieldNames.handleFriendInfo)) {
              if (!input.trySkipNullValue()) {
                input.readMessage(handleFriendInfo);
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
    public SyncHandleFriendScNotify clone() {
      return new SyncHandleFriendScNotify().copyFrom(this);
    }

    @Override
    public boolean isEmpty() {
      return ((bitField0_) == 0);
    }

    public static SyncHandleFriendScNotify parseFrom(final byte[] data) throws
        InvalidProtocolBufferException {
      return ProtoMessage.mergeFrom(new SyncHandleFriendScNotify(), data).checkInitialized();
    }

    public static SyncHandleFriendScNotify parseFrom(final ProtoSource input) throws IOException {
      return ProtoMessage.mergeFrom(new SyncHandleFriendScNotify(), input).checkInitialized();
    }

    public static SyncHandleFriendScNotify parseFrom(final JsonSource input) throws IOException {
      return ProtoMessage.mergeFrom(new SyncHandleFriendScNotify(), input).checkInitialized();
    }

    /**
     * @return factory for creating SyncHandleFriendScNotify messages
     */
    public static MessageFactory<SyncHandleFriendScNotify> getFactory() {
      return SyncHandleFriendScNotifyFactory.INSTANCE;
    }

    private enum SyncHandleFriendScNotifyFactory implements MessageFactory<SyncHandleFriendScNotify> {
      INSTANCE;

      @Override
      public SyncHandleFriendScNotify create() {
        return SyncHandleFriendScNotify.newInstance();
      }
    }

    /**
     * Contains name constants used for serializing JSON
     */
    static class FieldNames {
      static final FieldName uid = FieldName.forField("uid");

      static final FieldName handleResult = FieldName.forField("handleResult", "handle_result");

      static final FieldName handleFriendInfo = FieldName.forField("handleFriendInfo", "handle_friend_info");
    }
  }
}
