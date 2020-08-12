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

package google.registry.model.reporting;

import static com.google.common.truth.Truth.assertThat;
import static google.registry.persistence.transaction.TransactionManagerFactory.jpaTm;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import google.registry.model.EntityTestCase;
import google.registry.model.reporting.Spec11ThreatMatch.ThreatType;
import google.registry.persistence.transaction.JpaTransactionManager;
import org.joda.time.LocalDate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Unit tests for {@link Spec11ThreatMatchDao}. */
public class Spec11ThreatMatchDaoTest extends EntityTestCase {
  private static final LocalDate TODAY = new LocalDate(2020, 8, 4);
  private static final LocalDate YESTERDAY = new LocalDate(2020, 8, 3);

  Spec11ThreatMatchDaoTest() {
    super(JpaEntityCoverageCheck.ENABLED);
  }

  @BeforeEach
  void setUp() {
    jpaTm()
        .transact(
            () -> {
              jpaTm().saveNew(createThreatMatch("today.com", TODAY));
              jpaTm().saveNew(createThreatMatch("today.org", TODAY));
              jpaTm().saveNew(createThreatMatch("yesterday.com", YESTERDAY));
            });
  }

  @Test
  void testDeleteEntriesByDate() {
    JpaTransactionManager jpaTm = jpaTm();

    // Verify that all entries with the date TODAY were removed
    jpaTm.transact(
        () -> {
          Spec11ThreatMatchDao.deleteEntriesByDate(jpaTm, TODAY);
          ImmutableList<String> persistedToday =
              Spec11ThreatMatchDao.loadEntriesByDate(jpaTm, TODAY);
          assertThat(persistedToday).isEmpty();
        });

    // Verify that all other entries were not removed
    jpaTm.transact(
        () -> {
          ImmutableList<String> persistedYesterday =
              Spec11ThreatMatchDao.loadEntriesByDate(jpaTm, YESTERDAY);
          assertThat(persistedYesterday).contains("yesterday.com");
        });
  }

  @Test
  void testLoadEntriesByDate() {
    JpaTransactionManager jpaTm = jpaTm();
    jpaTm.transact(
        () -> {
          ImmutableList<String> persisted = Spec11ThreatMatchDao.loadEntriesByDate(jpaTm, TODAY);
          assertThat(persisted).contains("today.com");
          assertThat(persisted).contains("today.org");
        });
  }

  private Spec11ThreatMatch createThreatMatch(String domainName, LocalDate date) {
    Spec11ThreatMatch threatMatch =
        new Spec11ThreatMatch()
            .asBuilder()
            .setThreatTypes(ImmutableSet.of(ThreatType.MALWARE))
            .setCheckDate(date)
            .setDomainName(domainName)
            .setRegistrarId("Example Registrar")
            .setDomainRepoId("1-COM")
            .build();
    return threatMatch;
  }
}
