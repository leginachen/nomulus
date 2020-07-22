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

package google.registry.persistence;

import static com.google.common.truth.Truth.assertThat;

import google.registry.testing.DatastoreEntityExtension;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/** Unit tests for {@link PersistenceModule}. */
@Testcontainers
public class PersistenceModuleTest {

  @Container
  private final PostgreSQLContainer database =
      new PostgreSQLContainer(NomulusPostgreSql.getDockerTag());

  @RegisterExtension
  public DatastoreEntityExtension datastoreEntityExtension = new DatastoreEntityExtension();

  private EntityManagerFactory emf;

  @BeforeEach
  void init() {
    emf =
        PersistenceModule.create(
            database.getJdbcUrl(),
            database.getUsername(),
            database.getPassword(),
            PersistenceModule.provideDefaultDatabaseConfigs());
  }

  @AfterEach
  void destroy() {
    if (emf != null) {
      emf.close();
    }
    emf = null;
  }

  @Test
  void testConnectToDatabase_success() {
    EntityManager em = emf.createEntityManager();
    assertThat(em.isOpen()).isTrue();
    em.close();
  }
}
