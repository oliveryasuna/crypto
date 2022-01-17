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

import com.oliveryasuna.crypto.hash.*;
import com.oliveryasuna.crypto.util.Bytes;
import com.oliveryasuna.crypto.util.Keys;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class HMACTests {

  // Constructors
  //--------------------------------------------------

  private HMACTests() {
    super();
  }

  // Test methods
  //--------------------------------------------------

  // hmac_{HashFunction}_signAndVerify

  @Test
  final void hmac_md2_signAndVerify() throws Exception {
    final byte[] input = "Hello, World!".getBytes();
    final byte[] key = "key".getBytes();
    final byte[] expectedHash = "1f684f7b7b85383c1e539bd09a80218d".getBytes();

    final byte[] tag = new HMAC(key, MD2.getInstance()).sign(input);

    assertArrayEquals(expectedHash, Bytes.toHex(tag));
  }

  @Test
  final void hmac_md5_signAndVerify() throws Exception {
    final byte[] input = "Hello, World!".getBytes();
    final byte[] key = "key".getBytes();
    final byte[] expectedHash = "cfad9d610c1e548a03562f8eac399033".getBytes();

    final byte[] tag = new HMAC(key, MD5.getInstance()).sign(input);

    assertArrayEquals(expectedHash, Bytes.toHex(tag));
  }

  @Test
  final void hmac_sha1_signAndVerify() throws Exception {
    final byte[] input = "Hello, World!".getBytes();
    final byte[] key = "key".getBytes();
    final byte[] expectedHash = "b688f6f2602474b86713f193726755f0095edc8b".getBytes();

    final byte[] tag = new HMAC(key, SHA1.getInstance()).sign(input);

    assertArrayEquals(expectedHash, Bytes.toHex(tag));
  }

  @Test
  final void hmac_sha224_signAndVerify() throws Exception {
    final byte[] input = "Hello, World!".getBytes();
    final byte[] key = "key".getBytes();
    final byte[] expectedHash = "a58896726f469bc972de59f0304e3afcccd2fe2dd8c557f26280cb12".getBytes();

    final byte[] tag = new HMAC(key, SHA224.getInstance()).sign(input);

    assertArrayEquals(expectedHash, Bytes.toHex(tag));
  }

  @Test
  final void hmac_sha256_signAndVerify() throws Exception {
    final byte[] input = "Hello, World!".getBytes();
    final byte[] key = "key".getBytes();
    final byte[] expectedHash = "7f424e2d0ff6bd5dec626e0102755bafec91c3510f19739a4eaec8f3bc3a01a4".getBytes();

    final byte[] tag = new HMAC(key, SHA256.getInstance()).sign(input);

    assertArrayEquals(expectedHash, Bytes.toHex(tag));
  }

  @Test
  final void hmac_sha384_signAndVerify() throws Exception {
    final byte[] input = "Hello, World!".getBytes();
    final byte[] key = "key".getBytes();
    final byte[] expectedHash = "9fe103f87ef7dba0cda630259f21c261ced8b42b9dcdf5a17be91ee7c2435620459d891a720a84e2965365ea7cf36ef1".getBytes();

    final byte[] tag = new HMAC(key, SHA384.getInstance()).sign(input);

    assertArrayEquals(expectedHash, Bytes.toHex(tag));
  }

  @Test
  final void hmac_sha512_signAndVerify() throws Exception {
    final byte[] input = "Hello, World!".getBytes();
    final byte[] key = "key".getBytes();
    final byte[] expectedHash = "7b735ac190ebd1432d56f95ae2aea5a04a23128f4c228e299b7a49fb7561de8cc8f4fdf4486dc743dfd07827d617273aab42b3bf819d243ded322fac167419f1".getBytes();

    final byte[] tag = new HMAC(key, SHA512.getInstance()).sign(input);

    assertArrayEquals(expectedHash, Bytes.toHex(tag));
  }

  // hmac_{HashFunction}_generateAndSignAndVerify

  @Test
  final void hmac_md2_generateAndSignAndVerify() throws Exception {
    final byte[] input = "Hello, World!".getBytes();
    final HashFunction hashFunction = MD2.getInstance();

    final HMAC hmac = new HMAC(Keys.generate("AES"), hashFunction);

    final byte[] tag = hmac.sign(input);

    assertTrue(hmac.verify(input, tag));
  }

  @Test
  final void hmac_md5_generateAndSignAndVerify() throws Exception {
    final byte[] input = "Hello, World!".getBytes();
    final HashFunction hashFunction = MD5.getInstance();

    final HMAC hmac = new HMAC(Keys.generate("AES"), hashFunction);

    final byte[] tag = hmac.sign(input);

    assertTrue(hmac.verify(input, tag));
  }

  @Test
  final void hmac_sha1_generateAndSignAndVerify() throws Exception {
    final byte[] input = "Hello, World!".getBytes();
    final HashFunction hashFunction = SHA1.getInstance();

    final HMAC hmac = new HMAC(Keys.generate("AES"), hashFunction);

    final byte[] tag = hmac.sign(input);

    assertTrue(hmac.verify(input, tag));
  }

  @Test
  final void hmac_sha224_generateAndSignAndVerify() throws Exception {
    final byte[] input = "Hello, World!".getBytes();
    final HashFunction hashFunction = SHA224.getInstance();

    final HMAC hmac = new HMAC(Keys.generate("AES"), hashFunction);

    final byte[] tag = hmac.sign(input);

    assertTrue(hmac.verify(input, tag));
  }

  @Test
  final void hmac_sha256_generateAndSignAndVerify() throws Exception {
    final byte[] input = "Hello, World!".getBytes();
    final HashFunction hashFunction = SHA256.getInstance();

    final HMAC hmac = new HMAC(Keys.generate("AES"), hashFunction);

    final byte[] tag = hmac.sign(input);

    assertTrue(hmac.verify(input, tag));
  }

  @Test
  final void hmac_sha384_generateAndSignAndVerify() throws Exception {
    final byte[] input = "Hello, World!".getBytes();
    final HashFunction hashFunction = SHA384.getInstance();

    final HMAC hmac = new HMAC(Keys.generate("AES"), hashFunction);

    final byte[] tag = hmac.sign(input);

    assertTrue(hmac.verify(input, tag));
  }

  @Test
  final void hmac_sha512_generateAndSignAndVerify() throws Exception {
    final byte[] input = "Hello, World!".getBytes();
    final HashFunction hashFunction = SHA512.getInstance();

    final HMAC hmac = new HMAC(Keys.generate("AES"), hashFunction);

    final byte[] tag = hmac.sign(input);

    assertTrue(hmac.verify(input, tag));
  }

}
