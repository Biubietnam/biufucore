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
import us.hebi.quickbuf.RepeatedInt;

public final class ChessRogueStartCsReqOuterClass {
  /**
   * Protobuf type {@code ChessRogueStartCsReq}
   */
  public static final class ChessRogueStartCsReq extends ProtoMessage<ChessRogueStartCsReq> implements Cloneable {
    private static final long serialVersionUID = 0L;

    /**
     * <code>optional uint32 buff_aeon_id = 7;</code>
     */
    private int buffAeonId;

    /**
     * <code>optional uint32 LKCKPCJECJO = 9;</code>
     */
    private int lKCKPCJECJO;

    /**
     * <code>optional uint32 id = 10;</code>
     */
    private int id;

    /**
     * <code>repeated uint32 base_avatar_id_list = 1;</code>
     */
    private final RepeatedInt baseAvatarIdList = RepeatedInt.newEmptyInstance();

    /**
     * <code>repeated uint32 MOICCJNMBBI = 4;</code>
     */
    private final RepeatedInt mOICCJNMBBI = RepeatedInt.newEmptyInstance();

    /**
     * <code>repeated uint32 NGBFEHEJHHO = 6;</code>
     */
    private final RepeatedInt nGBFEHEJHHO = RepeatedInt.newEmptyInstance();

    /**
     * <code>repeated uint32 CCONMCFLBKG = 15;</code>
     */
    private final RepeatedInt cCONMCFLBKG = RepeatedInt.newEmptyInstance();

    private ChessRogueStartCsReq() {
    }

    /**
     * @return a new empty instance of {@code ChessRogueStartCsReq}
     */
    public static ChessRogueStartCsReq newInstance() {
      return new ChessRogueStartCsReq();
    }

    /**
     * <code>optional uint32 buff_aeon_id = 7;</code>
     * @return whether the buffAeonId field is set
     */
    public boolean hasBuffAeonId() {
      return (bitField0_ & 0x00000001) != 0;
    }

    /**
     * <code>optional uint32 buff_aeon_id = 7;</code>
     * @return this
     */
    public ChessRogueStartCsReq clearBuffAeonId() {
      bitField0_ &= ~0x00000001;
      buffAeonId = 0;
      return this;
    }

    /**
     * <code>optional uint32 buff_aeon_id = 7;</code>
     * @return the buffAeonId
     */
    public int getBuffAeonId() {
      return buffAeonId;
    }

    /**
     * <code>optional uint32 buff_aeon_id = 7;</code>
     * @param value the buffAeonId to set
     * @return this
     */
    public ChessRogueStartCsReq setBuffAeonId(final int value) {
      bitField0_ |= 0x00000001;
      buffAeonId = value;
      return this;
    }

    /**
     * <code>optional uint32 LKCKPCJECJO = 9;</code>
     * @return whether the lKCKPCJECJO field is set
     */
    public boolean hasLKCKPCJECJO() {
      return (bitField0_ & 0x00000002) != 0;
    }

    /**
     * <code>optional uint32 LKCKPCJECJO = 9;</code>
     * @return this
     */
    public ChessRogueStartCsReq clearLKCKPCJECJO() {
      bitField0_ &= ~0x00000002;
      lKCKPCJECJO = 0;
      return this;
    }

    /**
     * <code>optional uint32 LKCKPCJECJO = 9;</code>
     * @return the lKCKPCJECJO
     */
    public int getLKCKPCJECJO() {
      return lKCKPCJECJO;
    }

    /**
     * <code>optional uint32 LKCKPCJECJO = 9;</code>
     * @param value the lKCKPCJECJO to set
     * @return this
     */
    public ChessRogueStartCsReq setLKCKPCJECJO(final int value) {
      bitField0_ |= 0x00000002;
      lKCKPCJECJO = value;
      return this;
    }

    /**
     * <code>optional uint32 id = 10;</code>
     * @return whether the id field is set
     */
    public boolean hasId() {
      return (bitField0_ & 0x00000004) != 0;
    }

    /**
     * <code>optional uint32 id = 10;</code>
     * @return this
     */
    public ChessRogueStartCsReq clearId() {
      bitField0_ &= ~0x00000004;
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
    public ChessRogueStartCsReq setId(final int value) {
      bitField0_ |= 0x00000004;
      id = value;
      return this;
    }

    /**
     * <code>repeated uint32 base_avatar_id_list = 1;</code>
     * @return whether the baseAvatarIdList field is set
     */
    public boolean hasBaseAvatarIdList() {
      return (bitField0_ & 0x00000008) != 0;
    }

    /**
     * <code>repeated uint32 base_avatar_id_list = 1;</code>
     * @return this
     */
    public ChessRogueStartCsReq clearBaseAvatarIdList() {
      bitField0_ &= ~0x00000008;
      baseAvatarIdList.clear();
      return this;
    }

    /**
     * <code>repeated uint32 base_avatar_id_list = 1;</code>
     *
     * This method returns the internal storage object without modifying any has state.
     * The returned object should not be modified and be treated as read-only.
     *
     * Use {@link #getMutableBaseAvatarIdList()} if you want to modify it.
     *
     * @return internal storage object for reading
     */
    public RepeatedInt getBaseAvatarIdList() {
      return baseAvatarIdList;
    }

    /**
     * <code>repeated uint32 base_avatar_id_list = 1;</code>
     *
     * This method returns the internal storage object and sets the corresponding
     * has state. The returned object will become part of this message and its
     * contents may be modified as long as the has state is not cleared.
     *
     * @return internal storage object for modifications
     */
    public RepeatedInt getMutableBaseAvatarIdList() {
      bitField0_ |= 0x00000008;
      return baseAvatarIdList;
    }

    /**
     * <code>repeated uint32 base_avatar_id_list = 1;</code>
     * @param value the baseAvatarIdList to add
     * @return this
     */
    public ChessRogueStartCsReq addBaseAvatarIdList(final int value) {
      bitField0_ |= 0x00000008;
      baseAvatarIdList.add(value);
      return this;
    }

    /**
     * <code>repeated uint32 base_avatar_id_list = 1;</code>
     * @param values the baseAvatarIdList to add
     * @return this
     */
    public ChessRogueStartCsReq addAllBaseAvatarIdList(final int... values) {
      bitField0_ |= 0x00000008;
      baseAvatarIdList.addAll(values);
      return this;
    }

    /**
     * <code>repeated uint32 MOICCJNMBBI = 4;</code>
     * @return whether the mOICCJNMBBI field is set
     */
    public boolean hasMOICCJNMBBI() {
      return (bitField0_ & 0x00000010) != 0;
    }

    /**
     * <code>repeated uint32 MOICCJNMBBI = 4;</code>
     * @return this
     */
    public ChessRogueStartCsReq clearMOICCJNMBBI() {
      bitField0_ &= ~0x00000010;
      mOICCJNMBBI.clear();
      return this;
    }

    /**
     * <code>repeated uint32 MOICCJNMBBI = 4;</code>
     *
     * This method returns the internal storage object without modifying any has state.
     * The returned object should not be modified and be treated as read-only.
     *
     * Use {@link #getMutableMOICCJNMBBI()} if you want to modify it.
     *
     * @return internal storage object for reading
     */
    public RepeatedInt getMOICCJNMBBI() {
      return mOICCJNMBBI;
    }

    /**
     * <code>repeated uint32 MOICCJNMBBI = 4;</code>
     *
     * This method returns the internal storage object and sets the corresponding
     * has state. The returned object will become part of this message and its
     * contents may be modified as long as the has state is not cleared.
     *
     * @return internal storage object for modifications
     */
    public RepeatedInt getMutableMOICCJNMBBI() {
      bitField0_ |= 0x00000010;
      return mOICCJNMBBI;
    }

    /**
     * <code>repeated uint32 MOICCJNMBBI = 4;</code>
     * @param value the mOICCJNMBBI to add
     * @return this
     */
    public ChessRogueStartCsReq addMOICCJNMBBI(final int value) {
      bitField0_ |= 0x00000010;
      mOICCJNMBBI.add(value);
      return this;
    }

    /**
     * <code>repeated uint32 MOICCJNMBBI = 4;</code>
     * @param values the mOICCJNMBBI to add
     * @return this
     */
    public ChessRogueStartCsReq addAllMOICCJNMBBI(final int... values) {
      bitField0_ |= 0x00000010;
      mOICCJNMBBI.addAll(values);
      return this;
    }

    /**
     * <code>repeated uint32 NGBFEHEJHHO = 6;</code>
     * @return whether the nGBFEHEJHHO field is set
     */
    public boolean hasNGBFEHEJHHO() {
      return (bitField0_ & 0x00000020) != 0;
    }

    /**
     * <code>repeated uint32 NGBFEHEJHHO = 6;</code>
     * @return this
     */
    public ChessRogueStartCsReq clearNGBFEHEJHHO() {
      bitField0_ &= ~0x00000020;
      nGBFEHEJHHO.clear();
      return this;
    }

    /**
     * <code>repeated uint32 NGBFEHEJHHO = 6;</code>
     *
     * This method returns the internal storage object without modifying any has state.
     * The returned object should not be modified and be treated as read-only.
     *
     * Use {@link #getMutableNGBFEHEJHHO()} if you want to modify it.
     *
     * @return internal storage object for reading
     */
    public RepeatedInt getNGBFEHEJHHO() {
      return nGBFEHEJHHO;
    }

    /**
     * <code>repeated uint32 NGBFEHEJHHO = 6;</code>
     *
     * This method returns the internal storage object and sets the corresponding
     * has state. The returned object will become part of this message and its
     * contents may be modified as long as the has state is not cleared.
     *
     * @return internal storage object for modifications
     */
    public RepeatedInt getMutableNGBFEHEJHHO() {
      bitField0_ |= 0x00000020;
      return nGBFEHEJHHO;
    }

    /**
     * <code>repeated uint32 NGBFEHEJHHO = 6;</code>
     * @param value the nGBFEHEJHHO to add
     * @return this
     */
    public ChessRogueStartCsReq addNGBFEHEJHHO(final int value) {
      bitField0_ |= 0x00000020;
      nGBFEHEJHHO.add(value);
      return this;
    }

    /**
     * <code>repeated uint32 NGBFEHEJHHO = 6;</code>
     * @param values the nGBFEHEJHHO to add
     * @return this
     */
    public ChessRogueStartCsReq addAllNGBFEHEJHHO(final int... values) {
      bitField0_ |= 0x00000020;
      nGBFEHEJHHO.addAll(values);
      return this;
    }

    /**
     * <code>repeated uint32 CCONMCFLBKG = 15;</code>
     * @return whether the cCONMCFLBKG field is set
     */
    public boolean hasCCONMCFLBKG() {
      return (bitField0_ & 0x00000040) != 0;
    }

    /**
     * <code>repeated uint32 CCONMCFLBKG = 15;</code>
     * @return this
     */
    public ChessRogueStartCsReq clearCCONMCFLBKG() {
      bitField0_ &= ~0x00000040;
      cCONMCFLBKG.clear();
      return this;
    }

    /**
     * <code>repeated uint32 CCONMCFLBKG = 15;</code>
     *
     * This method returns the internal storage object without modifying any has state.
     * The returned object should not be modified and be treated as read-only.
     *
     * Use {@link #getMutableCCONMCFLBKG()} if you want to modify it.
     *
     * @return internal storage object for reading
     */
    public RepeatedInt getCCONMCFLBKG() {
      return cCONMCFLBKG;
    }

    /**
     * <code>repeated uint32 CCONMCFLBKG = 15;</code>
     *
     * This method returns the internal storage object and sets the corresponding
     * has state. The returned object will become part of this message and its
     * contents may be modified as long as the has state is not cleared.
     *
     * @return internal storage object for modifications
     */
    public RepeatedInt getMutableCCONMCFLBKG() {
      bitField0_ |= 0x00000040;
      return cCONMCFLBKG;
    }

    /**
     * <code>repeated uint32 CCONMCFLBKG = 15;</code>
     * @param value the cCONMCFLBKG to add
     * @return this
     */
    public ChessRogueStartCsReq addCCONMCFLBKG(final int value) {
      bitField0_ |= 0x00000040;
      cCONMCFLBKG.add(value);
      return this;
    }

    /**
     * <code>repeated uint32 CCONMCFLBKG = 15;</code>
     * @param values the cCONMCFLBKG to add
     * @return this
     */
    public ChessRogueStartCsReq addAllCCONMCFLBKG(final int... values) {
      bitField0_ |= 0x00000040;
      cCONMCFLBKG.addAll(values);
      return this;
    }

    @Override
    public ChessRogueStartCsReq copyFrom(final ChessRogueStartCsReq other) {
      cachedSize = other.cachedSize;
      if ((bitField0_ | other.bitField0_) != 0) {
        bitField0_ = other.bitField0_;
        buffAeonId = other.buffAeonId;
        lKCKPCJECJO = other.lKCKPCJECJO;
        id = other.id;
        baseAvatarIdList.copyFrom(other.baseAvatarIdList);
        mOICCJNMBBI.copyFrom(other.mOICCJNMBBI);
        nGBFEHEJHHO.copyFrom(other.nGBFEHEJHHO);
        cCONMCFLBKG.copyFrom(other.cCONMCFLBKG);
      }
      return this;
    }

    @Override
    public ChessRogueStartCsReq mergeFrom(final ChessRogueStartCsReq other) {
      if (other.isEmpty()) {
        return this;
      }
      cachedSize = -1;
      if (other.hasBuffAeonId()) {
        setBuffAeonId(other.buffAeonId);
      }
      if (other.hasLKCKPCJECJO()) {
        setLKCKPCJECJO(other.lKCKPCJECJO);
      }
      if (other.hasId()) {
        setId(other.id);
      }
      if (other.hasBaseAvatarIdList()) {
        getMutableBaseAvatarIdList().addAll(other.baseAvatarIdList);
      }
      if (other.hasMOICCJNMBBI()) {
        getMutableMOICCJNMBBI().addAll(other.mOICCJNMBBI);
      }
      if (other.hasNGBFEHEJHHO()) {
        getMutableNGBFEHEJHHO().addAll(other.nGBFEHEJHHO);
      }
      if (other.hasCCONMCFLBKG()) {
        getMutableCCONMCFLBKG().addAll(other.cCONMCFLBKG);
      }
      return this;
    }

    @Override
    public ChessRogueStartCsReq clear() {
      if (isEmpty()) {
        return this;
      }
      cachedSize = -1;
      bitField0_ = 0;
      buffAeonId = 0;
      lKCKPCJECJO = 0;
      id = 0;
      baseAvatarIdList.clear();
      mOICCJNMBBI.clear();
      nGBFEHEJHHO.clear();
      cCONMCFLBKG.clear();
      return this;
    }

    @Override
    public ChessRogueStartCsReq clearQuick() {
      if (isEmpty()) {
        return this;
      }
      cachedSize = -1;
      bitField0_ = 0;
      baseAvatarIdList.clear();
      mOICCJNMBBI.clear();
      nGBFEHEJHHO.clear();
      cCONMCFLBKG.clear();
      return this;
    }

    @Override
    public boolean equals(Object o) {
      if (o == this) {
        return true;
      }
      if (!(o instanceof ChessRogueStartCsReq)) {
        return false;
      }
      ChessRogueStartCsReq other = (ChessRogueStartCsReq) o;
      return bitField0_ == other.bitField0_
        && (!hasBuffAeonId() || buffAeonId == other.buffAeonId)
        && (!hasLKCKPCJECJO() || lKCKPCJECJO == other.lKCKPCJECJO)
        && (!hasId() || id == other.id)
        && (!hasBaseAvatarIdList() || baseAvatarIdList.equals(other.baseAvatarIdList))
        && (!hasMOICCJNMBBI() || mOICCJNMBBI.equals(other.mOICCJNMBBI))
        && (!hasNGBFEHEJHHO() || nGBFEHEJHHO.equals(other.nGBFEHEJHHO))
        && (!hasCCONMCFLBKG() || cCONMCFLBKG.equals(other.cCONMCFLBKG));
    }

    @Override
    public void writeTo(final ProtoSink output) throws IOException {
      if ((bitField0_ & 0x00000001) != 0) {
        output.writeRawByte((byte) 56);
        output.writeUInt32NoTag(buffAeonId);
      }
      if ((bitField0_ & 0x00000002) != 0) {
        output.writeRawByte((byte) 72);
        output.writeUInt32NoTag(lKCKPCJECJO);
      }
      if ((bitField0_ & 0x00000004) != 0) {
        output.writeRawByte((byte) 80);
        output.writeUInt32NoTag(id);
      }
      if ((bitField0_ & 0x00000008) != 0) {
        for (int i = 0; i < baseAvatarIdList.length(); i++) {
          output.writeRawByte((byte) 8);
          output.writeUInt32NoTag(baseAvatarIdList.array()[i]);
        }
      }
      if ((bitField0_ & 0x00000010) != 0) {
        for (int i = 0; i < mOICCJNMBBI.length(); i++) {
          output.writeRawByte((byte) 32);
          output.writeUInt32NoTag(mOICCJNMBBI.array()[i]);
        }
      }
      if ((bitField0_ & 0x00000020) != 0) {
        for (int i = 0; i < nGBFEHEJHHO.length(); i++) {
          output.writeRawByte((byte) 48);
          output.writeUInt32NoTag(nGBFEHEJHHO.array()[i]);
        }
      }
      if ((bitField0_ & 0x00000040) != 0) {
        for (int i = 0; i < cCONMCFLBKG.length(); i++) {
          output.writeRawByte((byte) 120);
          output.writeUInt32NoTag(cCONMCFLBKG.array()[i]);
        }
      }
    }

    @Override
    protected int computeSerializedSize() {
      int size = 0;
      if ((bitField0_ & 0x00000001) != 0) {
        size += 1 + ProtoSink.computeUInt32SizeNoTag(buffAeonId);
      }
      if ((bitField0_ & 0x00000002) != 0) {
        size += 1 + ProtoSink.computeUInt32SizeNoTag(lKCKPCJECJO);
      }
      if ((bitField0_ & 0x00000004) != 0) {
        size += 1 + ProtoSink.computeUInt32SizeNoTag(id);
      }
      if ((bitField0_ & 0x00000008) != 0) {
        size += (1 * baseAvatarIdList.length()) + ProtoSink.computeRepeatedUInt32SizeNoTag(baseAvatarIdList);
      }
      if ((bitField0_ & 0x00000010) != 0) {
        size += (1 * mOICCJNMBBI.length()) + ProtoSink.computeRepeatedUInt32SizeNoTag(mOICCJNMBBI);
      }
      if ((bitField0_ & 0x00000020) != 0) {
        size += (1 * nGBFEHEJHHO.length()) + ProtoSink.computeRepeatedUInt32SizeNoTag(nGBFEHEJHHO);
      }
      if ((bitField0_ & 0x00000040) != 0) {
        size += (1 * cCONMCFLBKG.length()) + ProtoSink.computeRepeatedUInt32SizeNoTag(cCONMCFLBKG);
      }
      return size;
    }

    @Override
    @SuppressWarnings("fallthrough")
    public ChessRogueStartCsReq mergeFrom(final ProtoSource input) throws IOException {
      // Enabled Fall-Through Optimization (QuickBuffers)
      int tag = input.readTag();
      while (true) {
        switch (tag) {
          case 56: {
            // buffAeonId
            buffAeonId = input.readUInt32();
            bitField0_ |= 0x00000001;
            tag = input.readTag();
            if (tag != 72) {
              break;
            }
          }
          case 72: {
            // lKCKPCJECJO
            lKCKPCJECJO = input.readUInt32();
            bitField0_ |= 0x00000002;
            tag = input.readTag();
            if (tag != 80) {
              break;
            }
          }
          case 80: {
            // id
            id = input.readUInt32();
            bitField0_ |= 0x00000004;
            tag = input.readTag();
            if (tag != 10) {
              break;
            }
          }
          case 10: {
            // baseAvatarIdList [packed=true]
            input.readPackedUInt32(baseAvatarIdList, tag);
            bitField0_ |= 0x00000008;
            tag = input.readTag();
            if (tag != 34) {
              break;
            }
          }
          case 34: {
            // mOICCJNMBBI [packed=true]
            input.readPackedUInt32(mOICCJNMBBI, tag);
            bitField0_ |= 0x00000010;
            tag = input.readTag();
            if (tag != 50) {
              break;
            }
          }
          case 50: {
            // nGBFEHEJHHO [packed=true]
            input.readPackedUInt32(nGBFEHEJHHO, tag);
            bitField0_ |= 0x00000020;
            tag = input.readTag();
            if (tag != 122) {
              break;
            }
          }
          case 122: {
            // cCONMCFLBKG [packed=true]
            input.readPackedUInt32(cCONMCFLBKG, tag);
            bitField0_ |= 0x00000040;
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
          case 8: {
            // baseAvatarIdList [packed=false]
            tag = input.readRepeatedUInt32(baseAvatarIdList, tag);
            bitField0_ |= 0x00000008;
            break;
          }
          case 32: {
            // mOICCJNMBBI [packed=false]
            tag = input.readRepeatedUInt32(mOICCJNMBBI, tag);
            bitField0_ |= 0x00000010;
            break;
          }
          case 48: {
            // nGBFEHEJHHO [packed=false]
            tag = input.readRepeatedUInt32(nGBFEHEJHHO, tag);
            bitField0_ |= 0x00000020;
            break;
          }
          case 120: {
            // cCONMCFLBKG [packed=false]
            tag = input.readRepeatedUInt32(cCONMCFLBKG, tag);
            bitField0_ |= 0x00000040;
            break;
          }
        }
      }
    }

    @Override
    public void writeTo(final JsonSink output) throws IOException {
      output.beginObject();
      if ((bitField0_ & 0x00000001) != 0) {
        output.writeUInt32(FieldNames.buffAeonId, buffAeonId);
      }
      if ((bitField0_ & 0x00000002) != 0) {
        output.writeUInt32(FieldNames.lKCKPCJECJO, lKCKPCJECJO);
      }
      if ((bitField0_ & 0x00000004) != 0) {
        output.writeUInt32(FieldNames.id, id);
      }
      if ((bitField0_ & 0x00000008) != 0) {
        output.writeRepeatedUInt32(FieldNames.baseAvatarIdList, baseAvatarIdList);
      }
      if ((bitField0_ & 0x00000010) != 0) {
        output.writeRepeatedUInt32(FieldNames.mOICCJNMBBI, mOICCJNMBBI);
      }
      if ((bitField0_ & 0x00000020) != 0) {
        output.writeRepeatedUInt32(FieldNames.nGBFEHEJHHO, nGBFEHEJHHO);
      }
      if ((bitField0_ & 0x00000040) != 0) {
        output.writeRepeatedUInt32(FieldNames.cCONMCFLBKG, cCONMCFLBKG);
      }
      output.endObject();
    }

    @Override
    public ChessRogueStartCsReq mergeFrom(final JsonSource input) throws IOException {
      if (!input.beginObject()) {
        return this;
      }
      while (!input.isAtEnd()) {
        switch (input.readFieldHash()) {
          case 864413617:
          case -1316781589: {
            if (input.isAtField(FieldNames.buffAeonId)) {
              if (!input.trySkipNullValue()) {
                buffAeonId = input.readUInt32();
                bitField0_ |= 0x00000001;
              }
            } else {
              input.skipUnknownField();
            }
            break;
          }
          case 12897171: {
            if (input.isAtField(FieldNames.lKCKPCJECJO)) {
              if (!input.trySkipNullValue()) {
                lKCKPCJECJO = input.readUInt32();
                bitField0_ |= 0x00000002;
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
                bitField0_ |= 0x00000004;
              }
            } else {
              input.skipUnknownField();
            }
            break;
          }
          case -1212654461:
          case 914628490: {
            if (input.isAtField(FieldNames.baseAvatarIdList)) {
              if (!input.trySkipNullValue()) {
                input.readRepeatedUInt32(baseAvatarIdList);
                bitField0_ |= 0x00000008;
              }
            } else {
              input.skipUnknownField();
            }
            break;
          }
          case -35824601: {
            if (input.isAtField(FieldNames.mOICCJNMBBI)) {
              if (!input.trySkipNullValue()) {
                input.readRepeatedUInt32(mOICCJNMBBI);
                bitField0_ |= 0x00000010;
              }
            } else {
              input.skipUnknownField();
            }
            break;
          }
          case -2145538198: {
            if (input.isAtField(FieldNames.nGBFEHEJHHO)) {
              if (!input.trySkipNullValue()) {
                input.readRepeatedUInt32(nGBFEHEJHHO);
                bitField0_ |= 0x00000020;
              }
            } else {
              input.skipUnknownField();
            }
            break;
          }
          case -1369452637: {
            if (input.isAtField(FieldNames.cCONMCFLBKG)) {
              if (!input.trySkipNullValue()) {
                input.readRepeatedUInt32(cCONMCFLBKG);
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
    public ChessRogueStartCsReq clone() {
      return new ChessRogueStartCsReq().copyFrom(this);
    }

    @Override
    public boolean isEmpty() {
      return ((bitField0_) == 0);
    }

    public static ChessRogueStartCsReq parseFrom(final byte[] data) throws
        InvalidProtocolBufferException {
      return ProtoMessage.mergeFrom(new ChessRogueStartCsReq(), data).checkInitialized();
    }

    public static ChessRogueStartCsReq parseFrom(final ProtoSource input) throws IOException {
      return ProtoMessage.mergeFrom(new ChessRogueStartCsReq(), input).checkInitialized();
    }

    public static ChessRogueStartCsReq parseFrom(final JsonSource input) throws IOException {
      return ProtoMessage.mergeFrom(new ChessRogueStartCsReq(), input).checkInitialized();
    }

    /**
     * @return factory for creating ChessRogueStartCsReq messages
     */
    public static MessageFactory<ChessRogueStartCsReq> getFactory() {
      return ChessRogueStartCsReqFactory.INSTANCE;
    }

    private enum ChessRogueStartCsReqFactory implements MessageFactory<ChessRogueStartCsReq> {
      INSTANCE;

      @Override
      public ChessRogueStartCsReq create() {
        return ChessRogueStartCsReq.newInstance();
      }
    }

    /**
     * Contains name constants used for serializing JSON
     */
    static class FieldNames {
      static final FieldName buffAeonId = FieldName.forField("buffAeonId", "buff_aeon_id");

      static final FieldName lKCKPCJECJO = FieldName.forField("LKCKPCJECJO");

      static final FieldName id = FieldName.forField("id");

      static final FieldName baseAvatarIdList = FieldName.forField("baseAvatarIdList", "base_avatar_id_list");

      static final FieldName mOICCJNMBBI = FieldName.forField("MOICCJNMBBI");

      static final FieldName nGBFEHEJHHO = FieldName.forField("NGBFEHEJHHO");

      static final FieldName cCONMCFLBKG = FieldName.forField("CCONMCFLBKG");
    }
  }
}
