// Copyright 2017 The Nomulus Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package google.registry.testing;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * JUnit extension for registering {@link BouncyCastleProvider} with Java Security.
 *
 * <p>This extension is necessary in order to use the {@code "BC"} provider of cryptographic
 * functions. Normally you would perform this registration in your {@code main()} function.
 *
 * @see BouncyCastleProvider
 * @see org.junit.jupiter.api.extension.Extension
 * @see java.security.Security#addProvider(java.security.Provider)
 */
public class BouncyCastleProviderExtension implements BeforeEachCallback, AfterEachCallback {

  @Override
  public void beforeEach(ExtensionContext context) {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Override
  public void afterEach(ExtensionContext context) {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
  }
}
