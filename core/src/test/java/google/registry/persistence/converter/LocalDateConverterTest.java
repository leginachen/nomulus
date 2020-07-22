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

package google.registry.persistence.converter;

import static com.google.common.truth.Truth.assertThat;
import static google.registry.persistence.transaction.TransactionManagerFactory.jpaTm;

import google.registry.model.ImmutableObject;
import google.registry.persistence.VKey;
import google.registry.persistence.transaction.JpaTestRules;
import google.registry.persistence.transaction.JpaTestRules.JpaUnitTestExtension;
import google.registry.schema.replay.EntityTest;
import javax.persistence.Entity;
import javax.persistence.Id;
import org.joda.time.LocalDate;
import org.joda.time.format.ISODateTimeFormat;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

/** Unit tests for {@link LocalDateConverter}. */
public class LocalDateConverterTest {

  @RegisterExtension
  public final JpaUnitTestExtension jpaExtension =
      new JpaTestRules.Builder()
          .withEntityClass(LocalDateConverterTestEntity.class)
          .buildUnitTestRule();

  private final LocalDate exampleDate = LocalDate.parse("2020-06-10", ISODateTimeFormat.date());

  @Test
  void testNullInput() {
    LocalDateConverterTestEntity retrievedEntity = persistAndLoadTestEntity(null);
    assertThat(retrievedEntity.date).isNull();
  }

  @Test
  void testSaveAndLoad_success() {
    LocalDateConverterTestEntity retrievedEntity = persistAndLoadTestEntity(exampleDate);
    assertThat(retrievedEntity.date).isEqualTo(exampleDate);
  }

  private LocalDateConverterTestEntity persistAndLoadTestEntity(LocalDate date) {
    LocalDateConverterTestEntity entity = new LocalDateConverterTestEntity(date);
    jpaTm().transact(() -> jpaTm().saveNew(entity));
    LocalDateConverterTestEntity retrievedEntity =
        jpaTm()
            .transact(() -> jpaTm().load(VKey.createSql(LocalDateConverterTestEntity.class, "id")));
    return retrievedEntity;
  }

  /** Override entity name to avoid the nested class reference. */
  @Entity(name = "LocalDateConverterTestEntity")
  @EntityTest.EntityForTesting
  private static class LocalDateConverterTestEntity extends ImmutableObject {

    @Id String name = "id";

    LocalDate date;

    public LocalDateConverterTestEntity() {}

    LocalDateConverterTestEntity(LocalDate date) {
      this.date = date;
    }
  }
}
