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

public final class UnlockTutorialGuideScRspOuterClass {
  /**
   * Protobuf type {@code UnlockTutorialGuideScRsp}
   */
  public static final class UnlockTutorialGuideScRsp extends ProtoMessage<UnlockTutorialGuideScRsp> implements Cloneable {
    private static final long serialVersionUID = 0L;

    /**
     * <pre>
     *  int64 ghhnodmgemk = 9;
     * </pre>
     *
     * <code>optional uint32 retcode = 12;</code>
     */
    private int retcode;

    /**
     * <code>optional .TutorialGuide tutorial_guide = 8;</code>
     */
    private final TutorialGuideOuterClass.TutorialGuide tutorialGuide = TutorialGuideOuterClass.TutorialGuide.newInstance();

    private UnlockTutorialGuideScRsp() {
    }

    /**
     * @return a new empty instance of {@code UnlockTutorialGuideScRsp}
     */
    public static UnlockTutorialGuideScRsp newInstance() {
      return new UnlockTutorialGuideScRsp();
    }

    /**
     * <pre>
     *  int64 ghhnodmgemk = 9;
     * </pre>
     *
     * <code>optional uint32 retcode = 12;</code>
     * @return whether the retcode field is set
     */
    public boolean hasRetcode() {
      return (bitField0_ & 0x00000001) != 0;
    }

    /**
     * <pre>
     *  int64 ghhnodmgemk = 9;
     * </pre>
     *
     * <code>optional uint32 retcode = 12;</code>
     * @return this
     */
    public UnlockTutorialGuideScRsp clearRetcode() {
      bitField0_ &= ~0x00000001;
      retcode = 0;
      return this;
    }

    /**
     * <pre>
     *  int64 ghhnodmgemk = 9;
     * </pre>
     *
     * <code>optional uint32 retcode = 12;</code>
     * @return the retcode
     */
    public int getRetcode() {
      return retcode;
    }

    /**
     * <pre>
     *  int64 ghhnodmgemk = 9;
     * </pre>
     *
     * <code>optional uint32 retcode = 12;</code>
     * @param value the retcode to set
     * @return this
     */
    public UnlockTutorialGuideScRsp setRetcode(final int value) {
      bitField0_ |= 0x00000001;
      retcode = value;
      return this;
    }

    /**
     * <code>optional .TutorialGuide tutorial_guide = 8;</code>
     * @return whether the tutorialGuide field is set
     */
    public boolean hasTutorialGuide() {
      return (bitField0_ & 0x00000002) != 0;
    }

    /**
     * <code>optional .TutorialGuide tutorial_guide = 8;</code>
     * @return this
     */
    public UnlockTutorialGuideScRsp clearTutorialGuide() {
      bitField0_ &= ~0x00000002;
      tutorialGuide.clear();
      return this;
    }

    /**
     * <code>optional .TutorialGuide tutorial_guide = 8;</code>
     *
     * This method returns the internal storage object without modifying any has state.
     * The returned object should not be modified and be treated as read-only.
     *
     * Use {@link #getMutableTutorialGuide()} if you want to modify it.
     *
     * @return internal storage object for reading
     */
    public TutorialGuideOuterClass.TutorialGuide getTutorialGuide() {
      return tutorialGuide;
    }

    /**
     * <code>optional .TutorialGuide tutorial_guide = 8;</code>
     *
     * This method returns the internal storage object and sets the corresponding
     * has state. The returned object will become part of this message and its
     * contents may be modified as long as the has state is not cleared.
     *
     * @return internal storage object for modifications
     */
    public TutorialGuideOuterClass.TutorialGuide getMutableTutorialGuide() {
      bitField0_ |= 0x00000002;
      return tutorialGuide;
    }

    /**
     * <code>optional .TutorialGuide tutorial_guide = 8;</code>
     * @param value the tutorialGuide to set
     * @return this
     */
    public UnlockTutorialGuideScRsp setTutorialGuide(
        final TutorialGuideOuterClass.TutorialGuide value) {
      bitField0_ |= 0x00000002;
      tutorialGuide.copyFrom(value);
      return this;
    }

    @Override
    public UnlockTutorialGuideScRsp copyFrom(final UnlockTutorialGuideScRsp other) {
      cachedSize = other.cachedSize;
      if ((bitField0_ | other.bitField0_) != 0) {
        bitField0_ = other.bitField0_;
        retcode = other.retcode;
        tutorialGuide.copyFrom(other.tutorialGuide);
      }
      return this;
    }

    @Override
    public UnlockTutorialGuideScRsp mergeFrom(final UnlockTutorialGuideScRsp other) {
      if (other.isEmpty()) {
        return this;
      }
      cachedSize = -1;
      if (other.hasRetcode()) {
        setRetcode(other.retcode);
      }
      if (other.hasTutorialGuide()) {
        getMutableTutorialGuide().mergeFrom(other.tutorialGuide);
      }
      return this;
    }

    @Override
    public UnlockTutorialGuideScRsp clear() {
      if (isEmpty()) {
        return this;
      }
      cachedSize = -1;
      bitField0_ = 0;
      retcode = 0;
      tutorialGuide.clear();
      return this;
    }

    @Override
    public UnlockTutorialGuideScRsp clearQuick() {
      if (isEmpty()) {
        return this;
      }
      cachedSize = -1;
      bitField0_ = 0;
      tutorialGuide.clearQuick();
      return this;
    }

    @Override
    public boolean equals(Object o) {
      if (o == this) {
        return true;
      }
      if (!(o instanceof UnlockTutorialGuideScRsp)) {
        return false;
      }
      UnlockTutorialGuideScRsp other = (UnlockTutorialGuideScRsp) o;
      return bitField0_ == other.bitField0_
        && (!hasRetcode() || retcode == other.retcode)
        && (!hasTutorialGuide() || tutorialGuide.equals(other.tutorialGuide));
    }

    @Override
    public void writeTo(final ProtoSink output) throws IOException {
      if ((bitField0_ & 0x00000001) != 0) {
        output.writeRawByte((byte) 96);
        output.writeUInt32NoTag(retcode);
      }
      if ((bitField0_ & 0x00000002) != 0) {
        output.writeRawByte((byte) 66);
        output.writeMessageNoTag(tutorialGuide);
      }
    }

    @Override
    protected int computeSerializedSize() {
      int size = 0;
      if ((bitField0_ & 0x00000001) != 0) {
        size += 1 + ProtoSink.computeUInt32SizeNoTag(retcode);
      }
      if ((bitField0_ & 0x00000002) != 0) {
        size += 1 + ProtoSink.computeMessageSizeNoTag(tutorialGuide);
      }
      return size;
    }

    @Override
    @SuppressWarnings("fallthrough")
    public UnlockTutorialGuideScRsp mergeFrom(final ProtoSource input) throws IOException {
      // Enabled Fall-Through Optimization (QuickBuffers)
      int tag = input.readTag();
      while (true) {
        switch (tag) {
          case 96: {
            // retcode
            retcode = input.readUInt32();
            bitField0_ |= 0x00000001;
            tag = input.readTag();
            if (tag != 66) {
              break;
            }
          }
          case 66: {
            // tutorialGuide
            input.readMessage(tutorialGuide);
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
        output.writeUInt32(FieldNames.retcode, retcode);
      }
      if ((bitField0_ & 0x00000002) != 0) {
        output.writeMessage(FieldNames.tutorialGuide, tutorialGuide);
      }
      output.endObject();
    }

    @Override
    public UnlockTutorialGuideScRsp mergeFrom(final JsonSource input) throws IOException {
      if (!input.beginObject()) {
        return this;
      }
      while (!input.isAtEnd()) {
        switch (input.readFieldHash()) {
          case 1097936398: {
            if (input.isAtField(FieldNames.retcode)) {
              if (!input.trySkipNullValue()) {
                retcode = input.readUInt32();
                bitField0_ |= 0x00000001;
              }
            } else {
              input.skipUnknownField();
            }
            break;
          }
          case 1686407742:
          case 1413565147: {
            if (input.isAtField(FieldNames.tutorialGuide)) {
              if (!input.trySkipNullValue()) {
                input.readMessage(tutorialGuide);
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
    public UnlockTutorialGuideScRsp clone() {
      return new UnlockTutorialGuideScRsp().copyFrom(this);
    }

    @Override
    public boolean isEmpty() {
      return ((bitField0_) == 0);
    }

    public static UnlockTutorialGuideScRsp parseFrom(final byte[] data) throws
        InvalidProtocolBufferException {
      return ProtoMessage.mergeFrom(new UnlockTutorialGuideScRsp(), data).checkInitialized();
    }

    public static UnlockTutorialGuideScRsp parseFrom(final ProtoSource input) throws IOException {
      return ProtoMessage.mergeFrom(new UnlockTutorialGuideScRsp(), input).checkInitialized();
    }

    public static UnlockTutorialGuideScRsp parseFrom(final JsonSource input) throws IOException {
      return ProtoMessage.mergeFrom(new UnlockTutorialGuideScRsp(), input).checkInitialized();
    }

    /**
     * @return factory for creating UnlockTutorialGuideScRsp messages
     */
    public static MessageFactory<UnlockTutorialGuideScRsp> getFactory() {
      return UnlockTutorialGuideScRspFactory.INSTANCE;
    }

    private enum UnlockTutorialGuideScRspFactory implements MessageFactory<UnlockTutorialGuideScRsp> {
      INSTANCE;

      @Override
      public UnlockTutorialGuideScRsp create() {
        return UnlockTutorialGuideScRsp.newInstance();
      }
    }

    /**
     * Contains name constants used for serializing JSON
     */
    static class FieldNames {
      static final FieldName retcode = FieldName.forField("retcode");

      static final FieldName tutorialGuide = FieldName.forField("tutorialGuide", "tutorial_guide");
    }
  }
}
