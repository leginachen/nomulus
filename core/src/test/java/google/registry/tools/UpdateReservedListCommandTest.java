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

package google.registry.tools;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth8.assertThat;
import static google.registry.model.registry.label.ReservationType.FULLY_BLOCKED;
import static google.registry.testing.DatastoreHelper.persistResource;
import static google.registry.util.DateTimeUtils.START_OF_TIME;
import static org.junit.Assert.assertThrows;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import google.registry.model.registry.label.ReservedList;
import google.registry.model.registry.label.ReservedList.ReservedListEntry;
import google.registry.model.registry.label.ReservedListSqlDao;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Unit tests for {@link UpdateReservedListCommand}. */
class UpdateReservedListCommandTest
    extends CreateOrUpdateReservedListCommandTestCase<UpdateReservedListCommand> {

  @BeforeEach
  void beforeEach() {
    populateInitialReservedListInDatastore(true);
  }

  private void populateInitialReservedListInDatastore(boolean shouldPublish) {
    persistResource(
        new ReservedList.Builder()
            .setName("xn--q9jyb4c_common-reserved")
            .setReservedListMapFromLines(ImmutableList.of("helicopter,FULLY_BLOCKED"))
            .setCreationTime(START_OF_TIME)
            .setLastUpdateTime(START_OF_TIME)
            .setShouldPublish(shouldPublish)
            .build());
  }

  private void populateInitialReservedListInCloudSql(boolean shouldPublish) {
    ReservedListSqlDao.save(
        createCloudSqlReservedList(
            "xn--q9jyb4c_common-reserved",
            fakeClock.nowUtc(),
            shouldPublish,
            ImmutableMap.of(
                "helicopter", ReservedListEntry.create("helicopter", FULLY_BLOCKED, ""))));
  }

  @Test
  void testSuccess() throws Exception {
    runSuccessfulUpdateTest("--name=xn--q9jyb4c_common-reserved", "--input=" + reservedTermsPath);
  }

  @Test
  void testSuccess_unspecifiedNameDefaultsToFileName() throws Exception {
    runSuccessfulUpdateTest("--input=" + reservedTermsPath);
  }

  @Test
  void testSuccess_lastUpdateTime_updatedCorrectly() throws Exception {
    ReservedList original = ReservedList.get("xn--q9jyb4c_common-reserved").get();
    runCommandForced("--input=" + reservedTermsPath);
    ReservedList updated = ReservedList.get("xn--q9jyb4c_common-reserved").get();
    assertThat(updated.getLastUpdateTime()).isGreaterThan(original.getLastUpdateTime());
    assertThat(updated.getCreationTime()).isEqualTo(original.getCreationTime());
    assertThat(updated.getLastUpdateTime()).isGreaterThan(updated.getCreationTime());
  }

  @Test
  void testSuccess_shouldPublish_setToFalseCorrectly() throws Exception {
    runSuccessfulUpdateTest("--input=" + reservedTermsPath, "--should_publish=false");
    assertThat(ReservedList.get("xn--q9jyb4c_common-reserved")).isPresent();
    ReservedList reservedList = ReservedList.get("xn--q9jyb4c_common-reserved").get();
    assertThat(reservedList.getShouldPublish()).isFalse();
  }

  @Test
  void testSuccess_shouldPublish_doesntOverrideFalseIfNotSpecified() throws Exception {
    populateInitialReservedListInDatastore(false);
    runCommandForced("--input=" + reservedTermsPath);
    assertThat(ReservedList.get("xn--q9jyb4c_common-reserved")).isPresent();
    ReservedList reservedList = ReservedList.get("xn--q9jyb4c_common-reserved").get();
    assertThat(reservedList.getShouldPublish()).isFalse();
  }

  private void runSuccessfulUpdateTest(String... args) throws Exception {
    runCommandForced(args);
    assertThat(ReservedList.get("xn--q9jyb4c_common-reserved")).isPresent();
    ReservedList reservedList = ReservedList.get("xn--q9jyb4c_common-reserved").get();
    assertThat(reservedList.getReservedListEntries()).hasSize(2);
    assertThat(reservedList.getReservationInList("baddies")).hasValue(FULLY_BLOCKED);
    assertThat(reservedList.getReservationInList("ford")).hasValue(FULLY_BLOCKED);
    assertThat(reservedList.getReservationInList("helicopter")).isEmpty();
  }

  @Test
  void testFailure_reservedListDoesntExist() {
    String errorMessage =
        "Could not update reserved list xn--q9jyb4c_poobah because it doesn't exist.";
    IllegalArgumentException thrown =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                runCommand("--force", "--name=xn--q9jyb4c_poobah", "--input=" + reservedTermsPath));
    assertThat(thrown).hasMessageThat().contains(errorMessage);
  }

  @Test
  void testSaveToCloudSql_succeeds() throws Exception {
    populateInitialReservedListInCloudSql(true);
    runCommandForced("--name=xn--q9jyb4c_common-reserved", "--input=" + reservedTermsPath);
    verifyXnq9jyb4cInDatastore();
    verifyXnq9jyb4cInCloudSql();
  }

  @Test
  void testSaveToCloudSql_succeedsEvenPreviousListNotExist() throws Exception {
    // Note that, during the dual-write phase, we always save the reserved list to Cloud SQL without
    // checking if there is a list with same name. This is to backfill the existing list in Cloud
    // Datastore when we update it.
    runCommandForced("--name=xn--q9jyb4c_common-reserved", "--input=" + reservedTermsPath);
    verifyXnq9jyb4cInDatastore();
    assertThat(ReservedListSqlDao.checkExists("xn--q9jyb4c_common-reserved")).isTrue();
  }
}
