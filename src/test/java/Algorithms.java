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

import com.oliveryasuna.commons.language.Arguments;
import com.oliveryasuna.commons.language.exception.UnsupportedInstantiationException;

import javax.crypto.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

final class Algorithms {

  // Main method
  //--------------------------------------------------

  public static void main(final String[] args) {
    final Set<Class<?>> types = Set.of(SecureRandom.class, MessageDigest.class, Signature.class, Cipher.class, Mac.class, KeyFactory.class,
        SecretKeyFactory.class, KeyPairGenerator.class, KeyGenerator.class, KeyAgreement.class, KeyStore.class, CertificateFactory.class);
    final Provider[] providers = Security.getProviders();

    for(final Class<?> type : types) {
      System.out.println("TYPE: " + type.getSimpleName());

      final Set<String> emptyProviders = new HashSet<>();

      for(final Provider provider : providers) {
        final Map<String, Set<String>> algorithmAliases = getAlgorithmAliases(provider, type);

        if(algorithmAliases.isEmpty()) {
          emptyProviders.add(provider.getName() + " " + provider.getVersionStr());

          continue;
        }

        System.out.println("\tPROVIDER: " + provider.getName() + " " + provider.getVersionStr());

        algorithmAliases.forEach((algorithm, aliases) -> {
          System.out.println("\t\tALGORITHM: " + algorithm);

          aliases.forEach(alias -> System.out.println("\t\t\tALIAS: " + alias));
        });
      }

      System.out.println("\tEMPTY PROVIDERS: " + String.join(", ", emptyProviders));
    }
  }

  // Static methods
  //--------------------------------------------------

  private static Map<String, Set<String>> getAlgorithmAliases(final Provider provider, final Class<?> type) {
    Arguments.requireNotNull(provider, "provider");
    Arguments.requireNotNull(type, "type");

    final String typeName = type.getSimpleName();
    final Set<Object> keys = provider.keySet();
    final String aliasPrefix = "Alg.Alias." + typeName + ".";

    return provider.getServices().stream()
        .filter(service -> service.getType().equalsIgnoreCase(typeName))
        .map(Provider.Service::getAlgorithm)
        .map(algorithm -> Map.entry(algorithm, keys.stream()
            .map(Object::toString)
            .filter(key -> key.startsWith(aliasPrefix))
            .map(key -> Map.entry(key, provider.get(key).toString()))
            .filter(entry -> entry.getValue().equalsIgnoreCase(algorithm))
            .map(Map.Entry::getKey)
            .map(alias -> alias.substring(aliasPrefix.length()))
            .collect(Collectors.toUnmodifiableSet())))
        .collect(Collectors.toUnmodifiableMap(Map.Entry::getKey, Map.Entry::getValue, (key1, key2) -> key1));
  }

  // Constructor
  //--------------------------------------------------

  private Algorithms() {
    super();

    throw new UnsupportedInstantiationException();
  }

}
