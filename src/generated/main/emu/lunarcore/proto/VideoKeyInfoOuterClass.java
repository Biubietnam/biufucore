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

public final class VideoKeyInfoOuterClass {
  /**
   * Protobuf type {@code VideoKeyInfo}
   */
  public static final class VideoKeyInfo extends ProtoMessage<VideoKeyInfo> implements Cloneable {
    private static final long serialVersionUID = 0L;

    /**
     * <code>optional uint64 video_key = 6;</code>
     */
    private long videoKey;

    /**
     * <code>optional uint32 id = 10;</code>
     */
    private int id;

    private VideoKeyInfo() {
    }

    /**
     * @return a new empty instance of {@code VideoKeyInfo}
     */
    public static VideoKeyInfo newInstance() {
      return new VideoKeyInfo();
    }

    /**
     * <code>optional uint64 video_key = 6;</code>
     * @return whether the videoKey field is set
     */
    public boolean hasVideoKey() {
      return (bitField0_ & 0x00000001) != 0;
    }

    /**
     * <code>optional uint64 video_key = 6;</code>
     * @return this
     */
    public VideoKeyInfo clearVideoKey() {
      bitField0_ &= ~0x00000001;
      videoKey = 0L;
      return this;
    }

    /**
     * <code>optional uint64 video_key = 6;</code>
     * @return the videoKey
     */
    public long getVideoKey() {
      return videoKey;
    }

    /**
     * <code>optional uint64 video_key = 6;</code>
     * @param value the videoKey to set
     * @return this
     */
    public VideoKeyInfo setVideoKey(final long value) {
      bitField0_ |= 0x00000001;
      videoKey = value;
      return this;
    }

    /**
     * <code>optional uint32 id = 10;</code>
     * @return whether the id field is set
     */
    public boolean hasId() {
      return (bitField0_ & 0x00000002) != 0;
    }

    /**
     * <code>optional uint32 id = 10;</code>
     * @return this
     */
    public VideoKeyInfo clearId() {
      bitField0_ &= ~0x00000002;
      id = 0;
      return this;
    }

    /**
     * <code>optional uint32 id = 10;</code>
     * @return the id
     */
    public int getId() {
      return id;
    }

    /**
     * <code>optional uint32 id = 10;</code>
     * @param value the id to set
     * @return this
     */
    public VideoKeyInfo setId(final int value) {
      bitField0_ |= 0x00000002;
      id = value;
      return this;
    }

    @Override
    public VideoKeyInfo copyFrom(final VideoKeyInfo other) {
      cachedSize = other.cachedSize;
      if ((bitField0_ | other.bitField0_) != 0) {
        bitField0_ = other.bitField0_;
        videoKey = other.videoKey;
        id = other.id;
      }
      return this;
    }

    @Override
    public VideoKeyInfo mergeFrom(final VideoKeyInfo other) {
      if (other.isEmpty()) {
        return this;
      }
      cachedSize = -1;
      if (other.hasVideoKey()) {
        setVideoKey(other.videoKey);
      }
      if (other.hasId()) {
        setId(other.id);
      }
      return this;
    }

    @Override
    public VideoKeyInfo clear() {
      if (isEmpty()) {
        return this;
      }
      cachedSize = -1;
      bitField0_ = 0;
      videoKey = 0L;
      id = 0;
      return this;
    }

    @Override
    public VideoKeyInfo clearQuick() {
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
      if (!(o instanceof VideoKeyInfo)) {
        return false;
      }
      VideoKeyInfo other = (VideoKeyInfo) o;
      return bitField0_ == other.bitField0_
        && (!hasVideoKey() || videoKey == other.videoKey)
        && (!hasId() || id == other.id);
    }

    @Override
    public void writeTo(final ProtoSink output) throws IOException {
      if ((bitField0_ & 0x00000001) != 0) {
        output.writeRawByte((byte) 48);
        output.writeUInt64NoTag(videoKey);
      }
      if ((bitField0_ & 0x00000002) != 0) {
        output.writeRawByte((byte) 80);
        output.writeUInt32NoTag(id);
      }
    }

    @Override
    protected int computeSerializedSize() {
      int size = 0;
      if ((bitField0_ & 0x00000001) != 0) {
        size += 1 + ProtoSink.computeUInt64SizeNoTag(videoKey);
      }
      if ((bitField0_ & 0x00000002) != 0) {
        size += 1 + ProtoSink.computeUInt32SizeNoTag(id);
      }
      return size;
    }

    @Override
    @SuppressWarnings("fallthrough")
    public VideoKeyInfo mergeFrom(final ProtoSource input) throws IOException {
      // Enabled Fall-Through Optimization (QuickBuffers)
      int tag = input.readTag();
      while (true) {
        switch (tag) {
          case 48: {
            // videoKey
            videoKey = input.readUInt64();
            bitField0_ |= 0x00000001;
            tag = input.readTag();
            if (tag != 80) {
              break;
            }
          }
          case 80: {
            // id
            id = input.readUInt32();
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
        output.writeUInt64(FieldNames.videoKey, videoKey);
      }
      if ((bitField0_ & 0x00000002) != 0) {
        output.writeUInt32(FieldNames.id, id);
      }
      output.endObject();
    }

    @Override
    public VideoKeyInfo mergeFrom(final JsonSource input) throws IOException {
      if (!input.beginObject()) {
        return this;
      }
      while (!input.isAtEnd()) {
        switch (input.readFieldHash()) {
          case 1151368164:
          case 1333275803: {
            if (input.isAtField(FieldNames.videoKey)) {
              if (!input.trySkipNullValue()) {
                videoKey = input.readUInt64();
                bitField0_ |= 0x00000001;
              }
            } else {
              input.skipUnknownField();
            }
            break;
          }
          case 3355: {
            if (input.isAtField(FieldNames.id)) {
              if (!input.trySkipNullValue()) {
                id = input.readUInt32();
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
    public VideoKeyInfo clone() {
      return new VideoKeyInfo().copyFrom(this);
    }

    @Override
    public boolean isEmpty() {
      return ((bitField0_) == 0);
    }

    public static VideoKeyInfo parseFrom(final byte[] data) throws InvalidProtocolBufferException {
      return ProtoMessage.mergeFrom(new VideoKeyInfo(), data).checkInitialized();
    }

    public static VideoKeyInfo parseFrom(final ProtoSource input) throws IOException {
      return ProtoMessage.mergeFrom(new VideoKeyInfo(), input).checkInitialized();
    }

    public static VideoKeyInfo parseFrom(final JsonSource input) throws IOException {
      return ProtoMessage.mergeFrom(new VideoKeyInfo(), input).checkInitialized();
    }

    /**
     * @return factory for creating VideoKeyInfo messages
     */
    public static MessageFactory<VideoKeyInfo> getFactory() {
      return VideoKeyInfoFactory.INSTANCE;
    }

    private enum VideoKeyInfoFactory implements MessageFactory<VideoKeyInfo> {
      INSTANCE;

      @Override
      public VideoKeyInfo create() {
        return VideoKeyInfo.newInstance();
      }
    }

    /**
     * Contains name constants used for serializing JSON
     */
    static class FieldNames {
      static final FieldName videoKey = FieldName.forField("videoKey", "video_key");

      static final FieldName id = FieldName.forField("id");
    }
  }
}
