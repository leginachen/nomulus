// Copyright 2019 The Nomulus Authors. All Rights Reserved.
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

package google.registry.persistence.transaction;

import google.registry.persistence.VKey;
import javax.persistence.EntityManager;

/** Sub-interface of {@link TransactionManager} which defines JPA related methods. */
public interface JpaTransactionManager extends TransactionManager {

  /** Returns the {@link EntityManager} for the current request. */
  EntityManager getEntityManager();

  /** Deletes the entity by its id, throws exception if the entity is not deleted. */
  public abstract <T> void assertDelete(VKey<T> key);

  /**
   * Releases all resources and shuts down.
   *
   * <p>The errorprone check forbids injection of {@link java.io.Closeable} resources.
   */
  void teardown();
}
