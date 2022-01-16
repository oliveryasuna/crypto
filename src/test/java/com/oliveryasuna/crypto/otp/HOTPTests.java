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

import com.oliveryasuna.crypto.hash.SHA1;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

final class HOTPTests {

  // Constructors
  //--------------------------------------------------

  private HOTPTests() {
    super();
  }

  // Test methods
  //--------------------------------------------------

  @Test
  final void hotp_sha1_compute0() throws Exception {
    final HOTP hotp = new HOTP(6, "12345678901234567890".getBytes(), SHA1.getInstance());
    final int otp = hotp.compute(0);

    assertEquals(otp, 755224);
  }

  @Test
  final void hotp_sha1_compute1() throws Exception {
    final HOTP hotp = new HOTP(6, "12345678901234567890".getBytes(), SHA1.getInstance());
    final int otp = hotp.compute(1);

    assertEquals(otp, 287082);
  }

  @Test
  final void hotp_sha1_compute2() throws Exception {
    final HOTP hotp = new HOTP(6, "12345678901234567890".getBytes(), SHA1.getInstance());
    final int otp = hotp.compute(2);

    assertEquals(otp, 359152);
  }

  @Test
  final void hotp_sha1_compute3() throws Exception {
    final HOTP hotp = new HOTP(6, "12345678901234567890".getBytes(), SHA1.getInstance());
    final int otp = hotp.compute(3);

    assertEquals(otp, 969429);
  }

  @Test
  final void hotp_sha1_compute4() throws Exception {
    final HOTP hotp = new HOTP(6, "12345678901234567890".getBytes(), SHA1.getInstance());
    final int otp = hotp.compute(4);

    assertEquals(otp, 338314);
  }

  @Test
  final void hotp_sha1_compute5() throws Exception {
    final HOTP hotp = new HOTP(6, "12345678901234567890".getBytes(), SHA1.getInstance());
    final int otp = hotp.compute(5);

    assertEquals(otp, 254676);
  }

  @Test
  final void hotp_sha1_compute6() throws Exception {
    final HOTP hotp = new HOTP(6, "12345678901234567890".getBytes(), SHA1.getInstance());
    final int otp = hotp.compute(6);

    assertEquals(otp, 287922);
  }

  @Test
  final void hotp_sha1_compute7() throws Exception {
    final HOTP hotp = new HOTP(6, "12345678901234567890".getBytes(), SHA1.getInstance());
    final int otp = hotp.compute(7);

    assertEquals(otp, 162583);
  }

  @Test
  final void hotp_sha1_compute8() throws Exception {
    final HOTP hotp = new HOTP(6, "12345678901234567890".getBytes(), SHA1.getInstance());
    final int otp = hotp.compute(8);

    assertEquals(otp, 399871);
  }

  @Test
  final void hotp_sha1_compute9() throws Exception {
    final HOTP hotp = new HOTP(6, "12345678901234567890".getBytes(), SHA1.getInstance());
    final int otp = hotp.compute(9);

    assertEquals(otp, 520489);
  }

}
