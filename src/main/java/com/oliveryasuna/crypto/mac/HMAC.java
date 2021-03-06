/*
 * Copyright 2022 Oliver Yasuna
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without
 *      specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.oliveryasuna.crypto.mac;

import com.oliveryasuna.commons.language.Arguments;
import com.oliveryasuna.commons.language.marker.Immutable;
import com.oliveryasuna.crypto.hash.HashFunction;
import com.oliveryasuna.crypto.util.Bytes;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

import java.util.Arrays;

/**
 * Represents a Hash-Based Message Authentication Code system.
 * <p>
 * HMAC is a MAC implementation backed by a cryptographic hash function.
 *
 * @author Oliver Yasuna
 */
@Immutable
public class HMAC implements IMAC {

  // Static fields
  //--------------------------------------------------

  public static final byte OUTER_PADDING_BYTE = 0x5c;

  public static final byte INNER_PADDING_BYTE = 0x36;

  // Constructors
  //--------------------------------------------------

  public HMAC(final byte[] key, final HashFunction hashFunction) throws Exception {
    super();

    Arguments.requireNotNull(key, "key");
    Arguments.requireNotNull(hashFunction, "hashFunction");

    this.key = key;
    this.hashFunction = hashFunction;

    final byte[][] paddedKeys = computePaddedKeys();

    this.outerPaddedKey = paddedKeys[0];
    this.innerPaddedKey = paddedKeys[1];
  }

  // Constructor helper methods
  //--------------------------------------------------

  private byte[][] computePaddedKeys() throws Exception {
    final byte[] blockSizedKey = computeBlockSizedKey(key, hashFunction);

    final byte[] outerPadding = new byte[hashFunction.blockSize()];
    final byte[] innerPadding = new byte[hashFunction.blockSize()];

    Arrays.fill(outerPadding, OUTER_PADDING_BYTE);
    Arrays.fill(innerPadding, INNER_PADDING_BYTE);

    final byte[] outerPaddedKey = Bytes.xor(blockSizedKey, outerPadding);
    final byte[] innerPaddedKey = Bytes.xor(blockSizedKey, innerPadding);

    return new byte[][] {outerPaddedKey, innerPaddedKey};
  }

  private byte[] computeBlockSizedKey(final byte[] key, final HashFunction hashFunction) throws Exception {
    final int blockSize = hashFunction.blockSize();

    if(key.length > blockSize) {
      // If the key's length is longer than the hash function's block size, then shorten it by hashing it.
      return hashFunction.compute(key);
    } else if(key.length < blockSize) {
      // If the key's length is shorter than the hash function's block size, then pad it with zeros on the right.
      return Arrays.copyOf(key, blockSize);
    } else {
      return key;
    }
  }

  // Fields
  //--------------------------------------------------

  protected final byte[] key;

  protected final byte[] outerPaddedKey;

  protected final byte[] innerPaddedKey;

  protected final HashFunction hashFunction;

  // IMAC methods
  //--------------------------------------------------

  @Override
  public byte[] sign(final byte[] message) throws Exception {
    Arguments.requireNotNull(message, "message");

    return hashFunction.compute(Bytes.concatenate(outerPaddedKey, hashFunction.compute(Bytes.concatenate(innerPaddedKey, message))));
  }

  @Override
  public boolean verify(final byte[] message, final byte[] tag) throws Exception {
    Arguments.requireNotNull(message, "message");
    Arguments.requireNotNull(tag, "tag");

    final byte[] expectedTag = sign(message);

    return Arrays.equals(expectedTag, tag);
  }

  // Getters
  //--------------------------------------------------

  public byte[] getKey() {
    return Arrays.copyOf(key, key.length);
  }

  public byte[] getOuterPaddedKey() {
    return outerPaddedKey.clone();
  }

  public byte[] getInnerPaddedKey() {
    return innerPaddedKey.clone();
  }

  public HashFunction getHashFunction() {
    return hashFunction;
  }

  // Object methods
  //--------------------------------------------------

  @Override
  public boolean equals(final Object object) {
    if(this == object) return true;
    if(object == null || getClass() != object.getClass()) return false;

    final HMAC objectCasted = (HMAC)object;

    return new EqualsBuilder()
        .append(key, objectCasted.key)
        .append(hashFunction, objectCasted.hashFunction)
        .isEquals();
  }

  @Override
  public int hashCode() {
    return new HashCodeBuilder(17, 37)
        .append(key)
        .append(hashFunction)
        .toHashCode();
  }

  @Override
  public String toString() {
    return new ToStringBuilder(this)
        .append("key", key)
        .append("outerPaddedKey", outerPaddedKey)
        .append("innerPaddedKey", innerPaddedKey)
        .append("hashFunction", hashFunction)
        .toString();
  }

}
