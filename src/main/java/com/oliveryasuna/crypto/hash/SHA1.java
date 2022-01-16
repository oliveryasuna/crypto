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

package com.oliveryasuna.crypto.hash;

import com.oliveryasuna.commons.language.Arguments;
import com.oliveryasuna.commons.language.marker.Immutable;
import com.oliveryasuna.commons.language.marker.Singleton;

import java.security.MessageDigest;

@Singleton
@Immutable
public class SHA1 implements HashFunction {

  // Singleton pattern
  //--------------------------------------------------

  private static final SHA1 INSTANCE = new SHA1();

  public static SHA1 getInstance() {
    return INSTANCE;
  }

  // Static fields
  //--------------------------------------------------

  public static final String ALGORITHM = "SHA-1";

  public static final int BLOCK_SIZE = 512 / 8;

  public static final int OUTPUT_SIZE = 160 / 8;

  // HashFunction methods
  //--------------------------------------------------

  @Override
  public byte[] compute(final byte[] input) throws Exception {
    Arguments.requireNotNull(input, "input");

    return MessageDigest.getInstance(ALGORITHM).digest(input);
  }

  @Override
  public final int blockSize() {
    return BLOCK_SIZE;
  }

  @Override
  public final int outputSize() {
    return OUTPUT_SIZE;
  }

}
