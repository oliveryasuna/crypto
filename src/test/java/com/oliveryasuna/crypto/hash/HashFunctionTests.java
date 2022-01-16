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

import com.oliveryasuna.crypto.util.Bytes;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

final class HashFunctionTests {

  // Constructors
  //--------------------------------------------------

  private HashFunctionTests() {
    super();
  }

  // Test methods
  //--------------------------------------------------

  @Test
  final void md2_computeAndVerify() throws Exception {
    final byte[] input = "Hello, World!".getBytes();
    final byte[] expectedHash = "1c8f1e6a94aaa7145210bf90bb52871a".getBytes();

    final byte[] hash = MD2.getInstance().compute(input);

    assertArrayEquals(expectedHash, Bytes.toHex(hash));
  }

  @Test
  final void md5_computeAndVerify() throws Exception {
    final byte[] input = "Hello, World!".getBytes();
    final byte[] expectedHash = "65a8e27d8879283831b664bd8b7f0ad4".getBytes();

    final byte[] hash = MD5.getInstance().compute(input);

    assertArrayEquals(expectedHash, Bytes.toHex(hash));
  }

  @Test
  final void sha1_computeAndVerify() throws Exception {
    final byte[] input = "Hello, World!".getBytes();
    final byte[] expectedHash = "0a0a9f2a6772942557ab5355d76af442f8f65e01".getBytes();

    final byte[] hash = SHA1.getInstance().compute(input);

    assertArrayEquals(expectedHash, Bytes.toHex(hash));
  }

  @Test
  final void sha224_computeAndVerify() throws Exception {
    final byte[] input = "Hello, World!".getBytes();
    final byte[] expectedHash = "72a23dfa411ba6fde01dbfabf3b00a709c93ebf273dc29e2d8b261ff".getBytes();

    final byte[] hash = SHA224.getInstance().compute(input);

    assertArrayEquals(expectedHash, Bytes.toHex(hash));
  }

  @Test
  final void sha256_computeAndVerify() throws Exception {
    final byte[] input = "Hello, World!".getBytes();
    final byte[] expectedHash = "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f".getBytes();

    final byte[] hash = SHA256.getInstance().compute(input);

    assertArrayEquals(expectedHash, Bytes.toHex(hash));
  }

  @Test
  final void sha384_computeAndVerify() throws Exception {
    final byte[] input = "Hello, World!".getBytes();
    final byte[] expectedHash = "5485cc9b3365b4305dfb4e8337e0a598a574f8242bf17289e0dd6c20a3cd44a089de16ab4ab308f63e44b1170eb5f515".getBytes();

    final byte[] hash = SHA384.getInstance().compute(input);

    assertArrayEquals(expectedHash, Bytes.toHex(hash));
  }

  @Test
  final void sha512_computeAndVerify() throws Exception {
    final byte[] input = "Hello, World!".getBytes();
    final byte[] expectedHash = "374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387".getBytes();

    final byte[] hash = SHA512.getInstance().compute(input);

    assertArrayEquals(expectedHash, Bytes.toHex(hash));
  }

}
