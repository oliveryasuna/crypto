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
import com.oliveryasuna.commons.language.marker.Singleton;
import com.oliveryasuna.crypto.hash.HashFunction;
import com.oliveryasuna.crypto.util.Bytes;
import com.oliveryasuna.crypto.util.Keys;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Represents a basic Message Authentication Code system.
 * <p>
 * MAC is backed by a cryptographic hash function.
 *
 * @author Oliver Yasuna
 */
@Singleton
@Immutable
public class MAC implements IMAC {

  // Singleton pattern
  //--------------------------------------------------

  private static final MAC INSTANCE = new MAC();

  public static MAC getInstance() {
    return INSTANCE;
  }

  // Constructors
  //--------------------------------------------------

  protected MAC() {
    super();
  }

  // MAC methods
  //--------------------------------------------------

  @Override
  public byte[] generateKey(final String algorithm) throws NoSuchAlgorithmException {
    Arguments.requireNotNull(algorithm, "algorithm");

    return Keys.generate(algorithm);
  }

  @Override
  public byte[] sign(final byte[] message, final byte[] key, final HashFunction hashFunction) throws Exception {
    Arguments.requireNotNull(message, "message");
    Arguments.requireNotNull(key, "key");
    Arguments.requireNotNull(hashFunction, "hashFunction");

    return hashFunction.compute(Bytes.concatenate(key, message));
  }

  @Override
  public boolean verify(final byte[] message, final byte[] tag, final byte[] key, final HashFunction hashFunction) throws Exception {
    Arguments.requireNotNull(message, "message");
    Arguments.requireNotNull(tag, "tag");
    Arguments.requireNotNull(key, "key");
    Arguments.requireNotNull(hashFunction, "hashFunction");

    final byte[] expectedTag = sign(message, key, hashFunction);

    return Arrays.equals(expectedTag, tag);
  }

}
