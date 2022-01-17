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
import com.oliveryasuna.crypto.util.Keys;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Represents a basic Message Authentication Code system.
 * <p>
 * MAC is backed by a cryptographic hash function.
 *
 * @author Oliver Yasuna
 */
@Immutable
public class MAC implements IMAC {

  // Constructors
  //--------------------------------------------------

  public MAC(final byte[] key, final HashFunction hashFunction) {
    super();

    Arguments.requireNotNull(key, "key");
    Arguments.requireNotNull(hashFunction, "hashFunction");

    this.key = key;
    this.hashFunction = hashFunction;
  }

  public MAC(final String keyAlgorithm, final HashFunction hashFunction) throws NoSuchAlgorithmException {
    this(Keys.generate(Arguments.requireNotNull(keyAlgorithm, "keyAlgorithm")), hashFunction);
  }

  // Fields
  //--------------------------------------------------

  private final byte[] key;

  private final HashFunction hashFunction;

  // IMAC methods
  //--------------------------------------------------

  @Override
  public byte[] sign(final byte[] message) throws Exception {
    Arguments.requireNotNull(message, "message");

    return hashFunction.compute(Bytes.concatenate(key, message));
  }

  @Override
  public boolean verify(final byte[] message, final byte[] tag) throws Exception {
    Arguments.requireNotNull(message, "message");
    Arguments.requireNotNull(tag, "tag");

    final byte[] expectedTag = sign(message);

    return Arrays.equals(expectedTag, tag);
  }

  // Object methods
  //--------------------------------------------------

  @Override
  public boolean equals(final Object object) {
    if(this == object) return true;
    if(object == null || getClass() != object.getClass()) return false;

    final MAC objectCasted = (MAC)object;

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
        .append("hashFunction", hashFunction)
        .toString();
  }

}
