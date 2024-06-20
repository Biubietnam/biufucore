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

public final class SelectChatBubbleCsReqOuterClass {
  /**
   * Protobuf type {@code SelectChatBubbleCsReq}
   */
  public static final class SelectChatBubbleCsReq extends ProtoMessage<SelectChatBubbleCsReq> implements Cloneable {
    private static final long serialVersionUID = 0L;

    /**
     * <pre>
     *  OIDCKALFNKH
     * </pre>
     *
     * <code>optional uint32 bubble_id = 9;</code>
     */
    private int bubbleId;

    private SelectChatBubbleCsReq() {
    }

    /**
     * @return a new empty instance of {@code SelectChatBubbleCsReq}
     */
    public static SelectChatBubbleCsReq newInstance() {
      return new SelectChatBubbleCsReq();
    }

    /**
     * <pre>
     *  OIDCKALFNKH
     * </pre>
     *
     * <code>optional uint32 bubble_id = 9;</code>
     * @return whether the bubbleId field is set
     */
    public boolean hasBubbleId() {
      return (bitField0_ & 0x00000001) != 0;
    }

    /**
     * <pre>
     *  OIDCKALFNKH
     * </pre>
     *
     * <code>optional uint32 bubble_id = 9;</code>
     * @return this
     */
    public SelectChatBubbleCsReq clearBubbleId() {
      bitField0_ &= ~0x00000001;
      bubbleId = 0;
      return this;
    }

    /**
     * <pre>
     *  OIDCKALFNKH
     * </pre>
     *
     * <code>optional uint32 bubble_id = 9;</code>
     * @return the bubbleId
     */
    public int getBubbleId() {
      return bubbleId;
    }

    /**
     * <pre>
     *  OIDCKALFNKH
     * </pre>
     *
     * <code>optional uint32 bubble_id = 9;</code>
     * @param value the bubbleId to set
     * @return this
     */
    public SelectChatBubbleCsReq setBubbleId(final int value) {
      bitField0_ |= 0x00000001;
      bubbleId = value;
      return this;
    }

    @Override
    public SelectChatBubbleCsReq copyFrom(final SelectChatBubbleCsReq other) {
      cachedSize = other.cachedSize;
      if ((bitField0_ | other.bitField0_) != 0) {
        bitField0_ = other.bitField0_;
        bubbleId = other.bubbleId;
      }
      return this;
    }

    @Override
    public SelectChatBubbleCsReq mergeFrom(final SelectChatBubbleCsReq other) {
      if (other.isEmpty()) {
        return this;
      }
      cachedSize = -1;
      if (other.hasBubbleId()) {
        setBubbleId(other.bubbleId);
      }
      return this;
    }

    @Override
    public SelectChatBubbleCsReq clear() {
      if (isEmpty()) {
        return this;
      }
      cachedSize = -1;
      bitField0_ = 0;
      bubbleId = 0;
      return this;
    }

    @Override
    public SelectChatBubbleCsReq clearQuick() {
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
      if (!(o instanceof SelectChatBubbleCsReq)) {
        return false;
      }
      SelectChatBubbleCsReq other = (SelectChatBubbleCsReq) o;
      return bitField0_ == other.bitField0_
        && (!hasBubbleId() || bubbleId == other.bubbleId);
    }

    @Override
    public void writeTo(final ProtoSink output) throws IOException {
      if ((bitField0_ & 0x00000001) != 0) {
        output.writeRawByte((byte) 72);
        output.writeUInt32NoTag(bubbleId);
      }
    }

    @Override
    protected int computeSerializedSize() {
      int size = 0;
      if ((bitField0_ & 0x00000001) != 0) {
        size += 1 + ProtoSink.computeUInt32SizeNoTag(bubbleId);
      }
      return size;
    }

    @Override
    @SuppressWarnings("fallthrough")
    public SelectChatBubbleCsReq mergeFrom(final ProtoSource input) throws IOException {
      // Enabled Fall-Through Optimization (QuickBuffers)
      int tag = input.readTag();
      while (true) {
        switch (tag) {
          case 72: {
            // bubbleId
            bubbleId = input.readUInt32();
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
        output.writeUInt32(FieldNames.bubbleId, bubbleId);
      }
      output.endObject();
    }

    @Override
    public SelectChatBubbleCsReq mergeFrom(final JsonSource input) throws IOException {
      if (!input.beginObject()) {
        return this;
      }
      while (!input.isAtEnd()) {
        switch (input.readFieldHash()) {
          case -1640052025:
          case 698016174: {
            if (input.isAtField(FieldNames.bubbleId)) {
              if (!input.trySkipNullValue()) {
                bubbleId = input.readUInt32();
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
    public SelectChatBubbleCsReq clone() {
      return new SelectChatBubbleCsReq().copyFrom(this);
    }

    @Override
    public boolean isEmpty() {
      return ((bitField0_) == 0);
    }

    public static SelectChatBubbleCsReq parseFrom(final byte[] data) throws
        InvalidProtocolBufferException {
      return ProtoMessage.mergeFrom(new SelectChatBubbleCsReq(), data).checkInitialized();
    }

    public static SelectChatBubbleCsReq parseFrom(final ProtoSource input) throws IOException {
      return ProtoMessage.mergeFrom(new SelectChatBubbleCsReq(), input).checkInitialized();
    }

    public static SelectChatBubbleCsReq parseFrom(final JsonSource input) throws IOException {
      return ProtoMessage.mergeFrom(new SelectChatBubbleCsReq(), input).checkInitialized();
    }

    /**
     * @return factory for creating SelectChatBubbleCsReq messages
     */
    public static MessageFactory<SelectChatBubbleCsReq> getFactory() {
      return SelectChatBubbleCsReqFactory.INSTANCE;
    }

    private enum SelectChatBubbleCsReqFactory implements MessageFactory<SelectChatBubbleCsReq> {
      INSTANCE;

      @Override
      public SelectChatBubbleCsReq create() {
        return SelectChatBubbleCsReq.newInstance();
      }
    }

    /**
     * Contains name constants used for serializing JSON
     */
    static class FieldNames {
      static final FieldName bubbleId = FieldName.forField("bubbleId", "bubble_id");
    }
  }
}
