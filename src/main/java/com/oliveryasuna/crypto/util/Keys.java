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

package com.oliveryasuna.crypto.util;

import com.oliveryasuna.commons.language.Arguments;
import com.oliveryasuna.commons.language.exception.UnsupportedInstantiationException;
import com.oliveryasuna.commons.language.marker.Utility;

import javax.crypto.KeyGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Various {@code static} key utilities.
 *
 * @author Oliver Yasuna
 */
@Utility
public final class Keys {

  // Static utility methods
  //--------------------------------------------------

  public static byte[] generate(final String algorithm, final SecureRandom secureRandom) throws NoSuchAlgorithmException {
    Arguments.requireNotNull(algorithm, "algorithm");
    Arguments.requireNotNull(secureRandom, "secureRandom");

    final KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);

    keyGenerator.init(secureRandom);

    return keyGenerator.generateKey().getEncoded();
  }

  public static byte[] generate(final String algorithm, final int keySize) throws NoSuchAlgorithmException {
    Arguments.requireNotNull(algorithm, "algorithm");

    final KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);

    keyGenerator.init(keySize);

    return keyGenerator.generateKey().getEncoded();
  }

  public static byte[] generate(final String algorithm) throws NoSuchAlgorithmException {
    return generate(algorithm, new SecureRandom());
  }

  // Constructors
  //--------------------------------------------------

  private Keys() {
    super();

    throw new UnsupportedInstantiationException();
  }

}
