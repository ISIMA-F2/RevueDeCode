package password;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Classe qui permet de hasher un mot de pass et calculer les distances entre
 * des mots.
 */
public class AwesomePasswordChecker {
  /**
   * Les lettres specifiques miniscule.
   */
  private static final Set<Character> LOWERCASE_VOWELS = new HashSet<>();
  /**
   * Les lettres specifiques majuscules.
   */
  private static final Set<Character> UPPERCASE_VOWELS = new HashSet<>();
  /**
   * les lettres specifiques spéciales.
   */
  private static final Set<Character> SPECIAL_CHARACTERS = new HashSet<>();

  static {
    for (char c : new char[] {'e', 's', 'a', 'i', 't', 'n', 'r', 'u', 'o', 'l'
    }) {
      LOWERCASE_VOWELS.add(c);
    }
    for (char c : new char[] {'E', 'S', 'A', 'I', 'T', 'N', 'R', 'U', 'O', 'L'
    }) {
      UPPERCASE_VOWELS.add(c);
    }
    for (char c : new char[] {'>', '<', '-', '?', '.', '/', '!', '%', '@', '&'
    }) {
      SPECIAL_CHARACTERS.add(c);
    }
  }
  /**
   * La Longeur maximale d'un mot de pass.
   */

  private static final int PASSWORD_LENGTH = 28;
  /**
   * Nombre de byte.
   */
  private static final int BYTE_NUMBER = 8;
  /**
   * Nombre de décalage.
   */
  private static final int DECALAGE = 6;
  /**
   * Hachage.
   */
  public static final int[] K = {
      0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
      0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
      0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
      0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
      0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
      0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
      0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
      0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
      0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
      0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
      0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
  };
  /**
   * Hachage2.
   */
  public static final int[] H = {
      0x67452301,
      0xefcdab89,
      0x98badcfe,
      0x10325476
  };
  /**
   * Hachage3.
   */
  public static final int[] R = {
      7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
      5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
  };
  /**
   * Huit.
   */
  public static final int HUIT = 8;
  /**
   * Huit.
   */
  public static final int SIEZE = 16;
  /**
   * L'instance Initiale.
   */
  private static AwesomePasswordChecker instance;
  /**
   * Liste des clusters sous formes de tableaux.
   */
  private final List<double[]> clusterCenters = new ArrayList<>();

  /**
   * Constructeur par défaut de la classe.
   */
  public AwesomePasswordChecker() {
  }

  /**
   * Constructeur privé qui charge les centres de clusters depuis un flux
   * d'entrée.
   *
   * @param is Le flux d'entrée contenant les données des centres de clusters.
   * @throws IOException Si une erreur de lecture se produit.
   */

  private AwesomePasswordChecker(final InputStream is) throws IOException {
    BufferedReader br = new BufferedReader(new InputStreamReader(is));
    String line;
    while ((line = br.readLine()) != null) {
      String[] values = line.split(";");
      double[] center = new double[values.length];

      for (int i = 0; i < values.length; ++i) {
        center[i] = Double.parseDouble(values[i]);
      }
      clusterCenters.add(center);
    }
    br.close();
  }

  /**
   * Retourne une instance unique de la classe AwesomePasswordChecker
   * en utilisant un fichier spécifié.
   *
   * @param file Le fichier contenant les centres de clusters à charger.
   * @return L'instance unique de AwesomePasswordChecker.
   * @throws IOException Si le fichier n'est pas accessible ou si une erreur de
   *                     lecture survient.
   */

  public static AwesomePasswordChecker getInstance(final File file)
      throws IOException {
    if (instance == null) {
      instance = new AwesomePasswordChecker(new FileInputStream(file));
    }
    return instance;
  }

  /**
   * Retourne l'instance unique de la classe AwesomePasswordChecker en utilisant
   * une ressource interne.
   *
   * @return L'instance unique de AwesomePasswordChecker.
   * @throws IOException Si la ressource est introuvable
   *                     ou une erreur de lecture survient.
   */
  public static AwesomePasswordChecker getInstance() throws IOException {
    if (instance == null) {
      InputStream is = AwesomePasswordChecker.class.getClassLoader()
          .getResourceAsStream("Files/cluster_centers_HAC_aff.csv");
      if (is == null) {
        throw new IOException("Fichier de ressource introuvable.");
      }
      instance = new AwesomePasswordChecker(is);
    }
    return instance;
  }

  /**
   * Génère un tableau de masques à partir d'un mot de passe donné.
   * Ce masque est utilisé pour analyser la composition du mot de passe.
   *
   * @param password Le mot de passe à analyser.
   * @return Un tableau d'entiers représentant le masque du mot de passe.
   */
  public int[] maskAff(final String password) {
    int[] maskArray = new int[PASSWORD_LENGTH];
    int limit = Math.min(password.length(), PASSWORD_LENGTH);

    for (int i = 0; i < limit; ++i) {
      char c = password.charAt(i);

      if (LOWERCASE_VOWELS.contains(c)) {
        maskArray[i] = 1;
      } else if (UPPERCASE_VOWELS.contains(c)) {
        maskArray[i] = 3;
      } else if (SPECIAL_CHARACTERS.contains(c)) {
        maskArray[i] = 6;
      } else if (Character.isLowerCase(c)) {
        maskArray[i] = 2;
      } else if (Character.isUpperCase(c)) {
        maskArray[i] = 4;
      } else if (Character.isDigit(c)) {
        maskArray[i] = 5;
      } else {
        maskArray[i] = 7;
      }
    }
    return maskArray;
  }

  /**
   * Calcule la distance euclidienne entre un mot de passe et les centres de
   * clusters.
   *
   * @param password Le mot de passe à analyser.
   * @return La distance euclidienne minimale entre le mot de passe
   *         et les centres de clusters.
   */
  public double getDistance(final String password) {
    int[] maskArray = maskAff(password);
    double minDistance = Double.MAX_VALUE;
    for (double[] center : clusterCenters) {
      minDistance = Math.min(euclideanDistance(maskArray, center), minDistance);
    }
    return minDistance;
  }

  /**
   * Calcule la distance euclidienne entre deux tableaux de valeurs.
   *
   * @param a Le premier tableau.
   * @param b Le second tableau.
   * @return La distance euclidienne entre les deux tableaux.
   */
  private double euclideanDistance(final int[] a, final double[] b) {
    double sum = 0;
    for (int i = 0; i < a.length; i++) {
      sum += (a[i] - b[i]) * (a[i] - b[i]);
    }
    return Math.sqrt(sum);
  }

  /**
   * Calcule le hachage MD5 d'une chaîne de caractères donnée.
   *
   * @param input La chaîne de caractères à hacher.
   * @return Le hachage MD5 sous forme de chaîne hexadécimale.
   */
  public static String computeMd5(final String input) {
    byte[] message = input.getBytes();
    int messageLenBytes = message.length;

    int numBlocks = ((messageLenBytes + BYTE_NUMBER) >>> DECALAGE) + 1;
    int totalLen = numBlocks << DECALAGE;
    byte[] paddingBytes = new byte[totalLen - messageLenBytes];
    paddingBytes[0] = (byte) 0x80;

    long messageLenBits = (long) messageLenBytes << 3;
    ByteBuffer lengthBuffer = ByteBuffer.allocate(HUIT).order(ByteOrder.LITTLE_ENDIAN)
        .putLong(messageLenBits);
    byte[] lengthBytes = lengthBuffer.array();

    byte[] paddedMessage = new byte[totalLen];
    System.arraycopy(message, 0, paddedMessage, 0, messageLenBytes);
    System.arraycopy(paddingBytes, 0, paddedMessage, messageLenBytes, paddingBytes.length);
    System.arraycopy(lengthBytes, 0, paddedMessage, totalLen - HUIT, HUIT);

    int[] h = H;

    int[] k = K;

    int[] r = R;

    for (int i = 0; i < numBlocks; i++) {
      int[] w = new int[SIEZE];
      for (int j = 0; j < SIEZE; j++) {
        w[j] = ByteBuffer.wrap(paddedMessage, (i << 6) + (j << 2), 4)
            .order(ByteOrder.LITTLE_ENDIAN).getInt();
      }

      int a = h[0];
      int b = h[1];
      int c = h[2];
      int d = h[3];

      for (int j = 0; j < 64; j++) {
        int f;
        int g;
        if (j < 16) {
          f = (b & c) | (~b & d);
          g = j;
        } else if (j < 32) {
          f = (d & b) | (~d & c);
          g = (5 * j + 1) % 16;
        } else if (j < 48) {
          f = b ^ c ^ d;
          g = (3 * j + 5) % 16;
        } else {
          f = c ^ (b | ~d);
          g = (7 * j) % 16;
        }
        final int temp = d;
        d = c;
        c = b;
        b = b + Integer.rotateLeft(a + f + k[j] + w[g], r[j]);
        a = temp;
      }

      h[0] += a;
      h[1] += b;
      h[2] += c;
      h[3] += d;
    }

    ByteBuffer md5Buffer = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
    md5Buffer.putInt(h[0]).putInt(h[1]).putInt(h[2]).putInt(h[3]);
    byte[] md5Bytes = md5Buffer.array();

    StringBuilder md5Hex = new StringBuilder();
    for (byte b : md5Bytes) {
      md5Hex.append(String.format("%02x", b));
    }

    return md5Hex.toString();
  }
}
