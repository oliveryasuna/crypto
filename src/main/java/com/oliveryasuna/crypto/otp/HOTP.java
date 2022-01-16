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

package com.oliveryasuna.crypto.otp;

import com.oliveryasuna.commons.language.Arguments;
import com.oliveryasuna.commons.language.marker.Immutable;
import com.oliveryasuna.crypto.hash.HashFunction;
import com.oliveryasuna.crypto.mac.HMAC;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

import java.nio.ByteBuffer;

@Immutable
public class HOTP {

  // Static fields
  //--------------------------------------------------

  /**
   * Calculated {@code Math.pow(10, length)}.
   */
  //                                 length = 0, 1,  2,   3,     4,      5,       6,         7,          8
  private static final int[] LENGTH_POWERS = {1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000};

  // Constructors
  //--------------------------------------------------

  public HOTP(final int length, final byte[] key, final HashFunction hashFunction) {
    super();

    Arguments.requireGreaterOrSame(length, 0, "length");
    Arguments.requireLess(length, LENGTH_POWERS.length, "length");
    Arguments.requireNotNull(key, "key");
    Arguments.requireNotNull(hashFunction, "hashFunction");

    this.length = length;
    this.modDivisor = LENGTH_POWERS[length];

    this.key = key;
    this.hashFunction = hashFunction;
  }

  // Fields
  //--------------------------------------------------

  protected final int length;

  protected final int modDivisor;

  protected final byte[] key;

  protected final HashFunction hashFunction;

  // Methods
  //--------------------------------------------------

  public int compute(final long counter) throws Exception {
    Arguments.requireGreaterOrSame(counter, 0, "counter");

    final ByteBuffer buffer = ByteBuffer.allocate(LENGTH_POWERS.length - 1);

    buffer.putLong(counter);

    final byte[] hash = HMAC.getInstance().sign(buffer.array(), key, hashFunction);

    final int offset = hash[hash.length - 1] & 0xf;
    final int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16) | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);

    return (binary % modDivisor);
  }

  // Getters
  //--------------------------------------------------

  public int getLength() {
    return length;
  }

  public byte[] getKey() {
    return key.clone();
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

    final HOTP objectCasted = (HOTP)object;

    return new EqualsBuilder()
        .append(length, objectCasted.length)
        .append(modDivisor, objectCasted.modDivisor)
        .append(key, objectCasted.key)
        .append(hashFunction, objectCasted.hashFunction)
        .isEquals();
  }

  @Override
  public int hashCode() {
    return new HashCodeBuilder(17, 37)
        .append(length)
        .append(modDivisor)
        .append(key)
        .append(hashFunction)
        .toHashCode();
  }

  @Override
  public String toString() {
    return new ToStringBuilder(this)
        .append("length", length)
        .append("modDivisor", modDivisor)
        .append("key", key)
        .append("hashFunction", hashFunction)
        .toString();
  }

}
