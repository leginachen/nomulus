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

package google.registry.tools.javascrap;

import static com.google.common.truth.Truth.assertThat;
import static google.registry.model.reporting.Spec11ThreatMatch.ThreatType.MALWARE;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.appengine.tools.cloudstorage.GcsFilename;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import google.registry.gcs.GcsUtils;
import google.registry.model.contact.ContactResource;
import google.registry.model.domain.DomainBase;
import google.registry.model.host.HostResource;
import google.registry.model.reporting.Spec11ThreatMatch;
import google.registry.model.transfer.ContactTransferData;
import google.registry.persistence.VKey;
import google.registry.persistence.transaction.JpaTransactionManager;
import google.registry.reporting.spec11.Spec11EmailUtils;
import google.registry.testing.TestDataHelper;
import google.registry.tools.CommandTestCase;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;
import org.joda.time.LocalDate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Unit tests for {@link BackfillSpec11ThreatMatchCommand}. */
public class BackfillSpec11ThreatMatchCommandTest
    extends CommandTestCase<BackfillSpec11ThreatMatchCommand> {
  private static final String TODAY = "2020-07-29";
  private static final String YESTERDAY = "2020-07-28";
  private static final Pattern FILENAME_PATTERN =
      Pattern.compile("SPEC11_MONTHLY_REPORT_(\\d{4}-\\d{2}-\\d{2})");

  private final GcsUtils mockGcsUtils = mock(GcsUtils.class);
  private final JpaTransactionManager mockJpaTm = mock(JpaTransactionManager.class);

  @BeforeEach
  public void setUp() throws IOException {
    command.gcsUtils = mockGcsUtils;
    command.jpaTm = mockJpaTm;
    setupFile("spec11_fake_report", TODAY);
    setupFile("spec11_fake_report_previous_day", YESTERDAY);

    persistDomains(); // Persist the domains needed for the Spec11ThreatMatch foreign key reference
  }

  @Test
  public void testGetDateFromFilename() {
    LocalDate dateCreated =
        command.getDateFromFilename("SPEC11_MONTHLY_REPORT_2020-07-29", FILENAME_PATTERN);
    assertThat(dateCreated.toString()).isEqualTo(TODAY);
  }

  @Test
  public void testGetSpec11ThreatMatchesFromFile() throws IOException {
    command.execute();

  }

  private Spec11ThreatMatch getThreatMatchesToday() {
    Spec11ThreatMatch threatA =
        new Spec11ThreatMatch.Builder()
            .setThreatTypes(ImmutableSet.of(MALWARE))
            .setCheckDate(LocalDate.parse(TODAY))
            .setDomainName("a.com")
            .setDomainRepoId("1-COM")
            .setRegistrarId("TheRegistrar")
            .build();

    Spec11ThreatMatch threatB =
        new Spec11ThreatMatch.Builder()
            .setThreatTypes(ImmutableSet.of(MALWARE))
            .setCheckDate(LocalDate.parse(TODAY))
            .setDomainName("b.com")
            .setDomainRepoId("1-COM")
            .setRegistrarId("NewRegistrar")
            .build();

    Spec11ThreatMatch threatC =
        new Spec11ThreatMatch.Builder()
            .setThreatTypes(ImmutableSet.of(MALWARE))
            .setCheckDate(LocalDate.parse(TODAY))
            .setDomainName("c.com")
            .setDomainRepoId("3-COM")
            .setRegistrarId("NewRegistrar")
            .build();

    return ImmutableList.of()
  }

  private void setupFile(String fileWithContent, String fileDate) throws IOException {
    GcsFilename gcsFilename =
        new GcsFilename(
            "test-bucket",
            String.format("icann/spec11/2020-07/SPEC11_MONTHLY_REPORT_%s", fileDate));
    when(mockGcsUtils.existsAndNotEmpty(gcsFilename)).thenReturn(true);
    when(mockGcsUtils.openInputStream(gcsFilename))
        .thenAnswer(
            (args) ->
                new ByteArrayInputStream(
                    loadFile(fileWithContent).getBytes(StandardCharsets.UTF_8)));
    when(mockGcsUtils.listFolderObjects("domain-registry-reporting", "SPEC11_MONTHLY_REPORT_"))
        .thenAnswer(
            (args) -> ImmutableList.of(String.format("%s%s", "SPEC11_MONTHLY_REPORT_", fileDate)));
  }

  private static String loadFile(String filename) {
    return TestDataHelper.loadFile(Spec11EmailUtils.class, filename);
  }

  private void persistDomains() {
    HostResource hostA =
        new HostResource.Builder()
            .setRepoId("hostA")
            .setHostName("ns1.example.com")
            .setCreationClientId("TheRegistrar")
            .setPersistedCurrentSponsorClientId("TheRegistrar")
            .build();
    HostResource hostB =
        new HostResource.Builder()
            .setRepoId("hostB")
            .setHostName("ns2.example.com")
            .setCreationClientId("NewRegistrar")
            .setPersistedCurrentSponsorClientId("NewRegistrar")
            .build();
    DomainBase domainA =
        new DomainBase()
            .asBuilder()
            .setCreationClientId("TheRegistrar")
            .setPersistedCurrentSponsorClientId("TheRegistrar")
            .setDomainName("a.com")
            .setRepoId("1-COM")
            .setNameservers(VKey.createSql(HostResource.class, "hostA"))
            .setRegistrant(VKey.createSql(ContactResource.class, "contact_id_A"))
            .setContacts(ImmutableSet.of())
            .build();
    DomainBase domainB =
        new DomainBase()
            .asBuilder()
            .setCreationClientId("NewRegistrar")
            .setPersistedCurrentSponsorClientId("NewRegistrar")
            .setDomainName("b.com")
            .setRepoId("2-COM")
            .setNameservers(VKey.createSql(HostResource.class, "hostB"))
            .setRegistrant(VKey.createSql(ContactResource.class, "contact_id_B"))
            .setContacts(ImmutableSet.of())
            .build();

    DomainBase domainC =
        new DomainBase()
            .asBuilder()
            .setCreationClientId("NewRegistrar")
            .setPersistedCurrentSponsorClientId("NewRegistrar")
            .setDomainName("c.com")
            .setRepoId("3-COM")
            .setNameservers(VKey.createSql(HostResource.class, "hostC"))
            .setRegistrant(VKey.createSql(ContactResource.class, "contact_id_C"))
            .setContacts(ImmutableSet.of())
            .build();

    ContactResource registrantContactA =
        new ContactResource.Builder()
            .setRepoId("contact_id_A")
            .setCreationClientId("TheRegistrar")
            .setTransferData(new ContactTransferData.Builder().build())
            .setPersistedCurrentSponsorClientId("TheRegistrar")
            .build();
    ContactResource registrantContactB =
        new ContactResource.Builder()
            .setRepoId("contact_id_B")
            .setCreationClientId("NewRegistrar")
            .setTransferData(new ContactTransferData.Builder().build())
            .setPersistedCurrentSponsorClientId("NewRegistrar")
            .build();

    mockJpaTm
        .transact(
            () -> {
              mockJpaTm.saveNew(registrantContactA);
              mockJpaTm.saveNew(registrantContactB);
              mockJpaTm.saveNew(domainA);
              mockJpaTm.saveNew(domainB);
              mockJpaTm.saveNew(hostA);
              mockJpaTm.saveNew(hostB);
            });
  }
}
