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

import java.util.Arrays;

@Utility
public final class Bytes {

  // Static utility methods
  //--------------------------------------------------

  public static byte[] concatenate(final byte[] array, final byte[]... arrays) {
    Arguments.requireNotNull(array, "array");
    // TODO: if(arrays != null) Arguments.requireNotContainsSame(arrays, null, "arrays");

    if(arrays == null) {
      return Arrays.copyOf(array, array.length);
    }

    byte[] result = array;

    for(final byte[] concat : arrays) {
      final byte[] temp = result;

      result = new byte[temp.length + concat.length];

      System.arraycopy(temp, 0, result, 0, temp.length);
      System.arraycopy(concat, 0, result, temp.length, concat.length);
    }

    return result;
  }

  public static byte[] xor(final byte[] array1, final byte[] array2) {
    Arguments.requireNotNull(array1, "array1");
    Arguments.requireNotNull(array2, "array2");
    Arguments.requireSame(array1.length, array2.length, "Length mismatch.");

    if(array1.length == 0) {
      return new byte[0];
    }

    final byte[] result = new byte[array1.length];

    for(int i = 0; i < array1.length; i++) {
      result[i] = (byte)(array1[i] ^ array2[i]);
    }

    return result;
  }

  public static byte[] toHex(final byte[] bytes) {
    Arguments.requireNotNull(bytes, "bytes");

    final StringBuilder hex = new StringBuilder(bytes.length * 2);

    for(final byte b : bytes) {
      hex.append(String.format("%02x", b));
    }

    return hex.toString().getBytes();
  }

  // Constructors
  //--------------------------------------------------

  private Bytes() {
    super();

    throw new UnsupportedInstantiationException();
  }

}
