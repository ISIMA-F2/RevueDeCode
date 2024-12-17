package password;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import org.junit.jupiter.api.Test;

/**
 * Classe des tests pour AwesomePasswordChecker.
 */
public class AwesomePasswordCheckerTest {
  @Test
    public void getInstanceTest() throws IOException {
    // Assurer que l'instance n'est pas null
    assertNotNull(AwesomePasswordChecker.getInstance(), "L'instance doit etre non null");
  }

  @Test
    public void getInstanceWihtParam() throws IOException {
    File f = new File("src\\main\\resources\\Files\\cluster_centers_HAC_aff.csv");
    assertNotNull(AwesomePasswordChecker.getInstance(f), "L'instance doit etre non null");
    File tempFile = File.createTempFile("1.987", ".txt");
    AwesomePasswordChecker result = AwesomePasswordChecker.getInstance(tempFile);
    assertNotNull(result);
    tempFile.delete();
  }

  @Test
    public void maskAffTest() {
    String a = "Na ><zZ9";
    AwesomePasswordChecker checker = new AwesomePasswordChecker();
    int[] tab = checker.maskAff(a);
    assertNotNull(tab);
    assertTrue(tab.length == 28, "La taille doit etre 28");
    // Verifier que le tableau correspond bien à la fonctionalité de la fonction
    // maskAff
    assertArrayEquals(
                new int[] { 3, 1, 7, 6, 6, 2, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, tab);
  }

  @Test
    public void getDistance() throws IOException {
    String test1 = "Na";
    double dist1 = AwesomePasswordChecker.getInstance().getDistance(test1);
    assertNotNull(dist1, "Avoir un resultat non numeral");
    // Assurer que la distance est une valeur numérique positive
    assertTrue(dist1 >= 0);
    assertEquals(4.63391363622807, dist1);
    // Tester avec le cas d'une chaine null
    String test2 = "";
    double dist2 = AwesomePasswordChecker.getInstance().getDistance(test2);
    assertTrue(dist2 == 5.073797971765403);
  }

  @Test
    public void md5HasherTest() {
    // Definir les test
    String motCourt = "Nasri";
    String motLong = "fghfbshfdyfgsbekhfse";
    String motCaractereSpecial = "&àçà&)àé&ééàé$ù$$£%£";
    // Tester chaque cas
    testDePerformance(motCourt, "Mot court");
    testDePerformance(motLong, "Mot long");
    testDePerformance(motCaractereSpecial,
        "Mot avec des caractères spéciaux");

  }

  private void testDePerformance(String input, String description) {
    int iterations = 1000;
    long tempsTotal = 0;
    for (int i = 0; i < iterations; i++) {
      long debut = System.nanoTime();
      String result = AwesomePasswordChecker.computeMd5(input);
      long fin = System.nanoTime();
      tempsTotal += (fin - debut);
      assertNotNull(result, "Le résultat ne doit pas etre null");
    }
    double tempsMoyen = tempsTotal / (double) iterations;
    System.out.printf("%s: Temps moyen d'executions est :  %.2f nanoseconds (%d iterations)%n",
            description, tempsMoyen, iterations);
  }
}
