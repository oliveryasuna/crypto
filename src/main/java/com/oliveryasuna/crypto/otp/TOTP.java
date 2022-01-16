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

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

@Immutable
public class TOTP {

  // Constructors
  //--------------------------------------------------

  public TOTP(final int length, final Duration timeStep, final Instant startTime, final byte[] key, final HashFunction hashFunction) {
    super();

    Arguments.requireNotNull(timeStep, "timeStep");
    Arguments.requireFalse(timeStep.isZero(), "timeStep");
    Arguments.requireFalse(timeStep.isNegative(), "timeStep");
    Arguments.requireNotNull(startTime, "startTime");

    this.hotp = new HOTP(length, key, hashFunction);

    this.timeStep = timeStep;
    this.timeStepMillis = timeStep.toMillis();

    this.startTime = startTime;
    this.startTimeMillis = startTime.toEpochMilli();
  }

  public TOTP(final int length, final Duration timeStep, final byte[] key, final HashFunction hashFunction) {
    this(length, timeStep, Instant.now(), key, hashFunction);
  }

  // Fields
  //--------------------------------------------------

  protected HOTP hotp;

  protected final Duration timeStep;

  protected final long timeStepMillis;

  protected final Instant startTime;

  protected final long startTimeMillis;

  // Methods
  //--------------------------------------------------

  public int compute(final Instant time) throws Exception {
    Arguments.requireNotNull(time, "time");
    Arguments.requireGreaterOrSame(time, getStartTime(), "time");

    return hotp.compute(computeCounter(time));
  }

  private long computeCounter(final Instant time) {
    return ((time.toEpochMilli() - startTimeMillis) / timeStepMillis);
  }

  // Getters
  //--------------------------------------------------

  public Duration getTimeStep() {
    return timeStep;
  }

  public Instant getStartTime() {
    return startTime;
  }

  // Object methods
  //--------------------------------------------------

  @Override
  public boolean equals(final Object object) {
    if(this == object) return true;
    if(object == null || getClass() != object.getClass()) return false;

    final TOTP objectCasted = (TOTP)object;

    return (hotp.equals(objectCasted.hotp) && timeStep.equals(objectCasted.timeStep) && startTime.equals(objectCasted.startTime));
  }

  @Override
  public int hashCode() {
    return Objects.hash(hotp, timeStep, startTime);
  }

  @Override
  public String toString() {
    return ("TOTP{" +
        "hotp=" + hotp +
        ", timeStep=" + timeStep +
        ", timeStepMillis=" + timeStepMillis +
        ", startTime=" + startTime +
        ", startTimeMillis=" + startTimeMillis +
        '}');
  }

}
