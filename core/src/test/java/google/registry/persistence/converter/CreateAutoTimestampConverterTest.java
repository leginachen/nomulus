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
package google.registry.persistence.converter;

import static com.google.common.truth.Truth.assertThat;
import static google.registry.persistence.transaction.TransactionManagerFactory.jpaTm;

import google.registry.model.CreateAutoTimestamp;
import google.registry.model.ImmutableObject;
import google.registry.persistence.transaction.JpaTestRules;
import google.registry.persistence.transaction.JpaTestRules.JpaUnitTestExtension;
import google.registry.schema.replay.EntityTest.EntityForTesting;
import google.registry.testing.FakeClock;
import javax.persistence.Entity;
import javax.persistence.Id;
import org.joda.time.DateTime;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

/** Unit tests for {@link CreateAutoTimestampConverter}. */
public class CreateAutoTimestampConverterTest {

  private final FakeClock fakeClock = new FakeClock();

  @RegisterExtension
  public final JpaUnitTestExtension jpaExtension =
      new JpaTestRules.Builder()
          .withClock(fakeClock)
          .withEntityClass(TestEntity.class)
          .buildUnitTestRule();

  @Test
  void testTypeConversion() {
    CreateAutoTimestamp ts = CreateAutoTimestamp.create(DateTime.parse("2019-09-9T11:39:00Z"));
    TestEntity ent = new TestEntity("myinst", ts);

    jpaTm().transact(() -> jpaTm().getEntityManager().persist(ent));
    TestEntity result =
        jpaTm().transact(() -> jpaTm().getEntityManager().find(TestEntity.class, "myinst"));
    assertThat(result).isEqualTo(new TestEntity("myinst", ts));
  }

  @Test
  void testAutoInitialization() {
    CreateAutoTimestamp ts = CreateAutoTimestamp.create(null);
    TestEntity ent = new TestEntity("autoinit", ts);

    jpaTm().transact(() -> jpaTm().getEntityManager().persist(ent));

    TestEntity result =
        jpaTm().transact(() -> jpaTm().getEntityManager().find(TestEntity.class, "autoinit"));
    assertThat(result.cat.getTimestamp()).isEqualTo(fakeClock.nowUtc());
  }

  @Entity(name = "TestEntity") // Override entity name to avoid the nested class reference.
  @EntityForTesting
  public static class TestEntity extends ImmutableObject {

    @Id String name;

    CreateAutoTimestamp cat;

    public TestEntity() {}

    TestEntity(String name, CreateAutoTimestamp cat) {
      this.name = name;
      this.cat = cat;
    }
  }
}
