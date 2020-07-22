// Copyright 2020 The Nomulus Authors. All Rights Reserved.
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

package google.registry.beam.initsql;

import static com.google.common.truth.Truth.assertThat;

import google.registry.persistence.NomulusPostgreSql;
import google.registry.persistence.transaction.JpaTransactionManager;
import google.registry.testing.DatastoreEntityExtension;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import org.apache.beam.sdk.io.FileSystems;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/** Unit tests for {@link BeamJpaModule}. */
@Testcontainers
public class BeamJpaModuleTest {

  @Container
  public PostgreSQLContainer database = new PostgreSQLContainer(NomulusPostgreSql.getDockerTag());

  @RegisterExtension
  public DatastoreEntityExtension datastoreEntityExtension = new DatastoreEntityExtension();

  @TempDir File tempFolder;

  private File credentialFile;

  @BeforeEach
  public void beforeEach() throws IOException {
    credentialFile = new File(tempFolder, "credential");
    new PrintStream(credentialFile)
        .printf("%s %s %s", database.getJdbcUrl(), database.getUsername(), database.getPassword())
        .close();
  }

  @Test
  void getJpaTransactionManager_local() {
    JpaTransactionManager jpa =
        DaggerBeamJpaModule_JpaTransactionManagerComponent.builder()
            .beamJpaModule(new BeamJpaModule(credentialFile.getAbsolutePath()))
            .build()
            .localDbJpaTransactionManager();
    assertThat(
            jpa.transact(
                () -> jpa.getEntityManager().createNativeQuery("select 1").getSingleResult()))
        .isEqualTo(1);
  }

  /**
   * Integration test with a GCP project, only run when the 'test.gcp_integration.env' property is
   * defined. Otherwise this test is ignored. This is meant to be run from a developer's desktop,
   * with auth already set up by gcloud.
   *
   * <p>Example: {@code gradlew test -P test.gcp_integration.env=alpha}.
   *
   * <p>See <a href="../../../../../../../../java_common.gradle">java_common.gradle</a> for more
   * information.
   */
  @Test
  @EnabledIfSystemProperty(named = "test.gcp_integration.env", matches = "\\S+")
  public void getJpaTransactionManager_cloudSql_authRequired() {
    String environmentName = System.getProperty("test.gcp_integration.env");
    FileSystems.setDefaultPipelineOptions(PipelineOptionsFactory.create());
    JpaTransactionManager jpa =
        DaggerBeamJpaModule_JpaTransactionManagerComponent.builder()
            .beamJpaModule(
                new BeamJpaModule(
                    BackupPaths.getCloudSQLCredentialFilePatterns(environmentName).get(0)))
            .build()
            .cloudSqlJpaTransactionManager();
    assertThat(
            jpa.transact(
                () -> jpa.getEntityManager().createNativeQuery("select 1").getSingleResult()))
        .isEqualTo(1);
  }
}
