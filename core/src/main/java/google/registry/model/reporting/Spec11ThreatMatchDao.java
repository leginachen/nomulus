package google.registry.model.reporting;

import google.registry.persistence.transaction.JpaTransactionManager;
import org.joda.time.LocalDate;

/** Data access object for {@link google.registry.model.reporting.Spec11ThreatMatch} */
public class Spec11ThreatMatchDao {
  public static void deleteEntriesByDate(JpaTransactionManager jpaTm, LocalDate date) {
    jpaTm.assertInTransaction();
    jpaTm
        .getEntityManager()
        .createQuery(
            "DELETE FROM \"Spec11ThreatMatch\""
            + " WHERE check_date = :date"
        )
        .setParameter("date", date);
  }
}
