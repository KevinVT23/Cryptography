import java.awt.desktop.SystemEventListener;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.sql.SQLSyntaxErrorException;
import java.util.Arrays;
import java.io.IOException;
import java.io.File;
import java.io.FileWriter;   // Import the FileWriter class
import java.util.*;

public class Main {

    public static void main(String[] args) {
        // These are some manual tests, one of which is against a KMACXOF256 provided test vector
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMACXOF_samples.pdf
//        manualTests(); // Tests for correctness and for the hash, MAC, decrypt and encrypt;

        System.out.println(Curved.P_448);
        System.out.println(Curved.R_448);

        Curved curve = new Curved();

        System.out.println(curve);

        curve.CurvedG();

        System.out.println(curve);

        //Curved.tests(); Test curves, it will output errors if it fails any test.

      
        Scanner scanner = new Scanner(System.in);

        System.out.println("Would you like to 1) generate a key pair 2) Encrypt a message with a public key " +
                "3) Decrypt with a private key 4) Generate a Signature 5) Verify a signature?");
        int choice = Integer.parseInt(scanner.nextLine());
        if (choice == 1) {
            System.out.println("What file would you like to write to? {name}.txt");
            String fileName = scanner.nextLine();
            System.out.println("Whats the password you would like to use?");
            String pw = scanner.nextLine();

            generateKeyPair(fileName, pw);
        } else if (choice == 2) {
            System.out.println("What file would you like to encrypt? {name}.txt");
            String fileName = scanner.nextLine();
            encrypt(fileName);
        } else if (choice == 3) {
            System.out.println("What file would you like to decrypt? {name}.txt");
            String fileName = scanner.nextLine();
            System.out.println("Whats the password did you use?");
            String pw = scanner.nextLine();
            decrypt(fileName, pw);
        } else if (choice == 4) {
//            Generating a signature for a byte array m under passphrase pw:
//            s  KMACXOF256(pw, “”, 448, “SK”); s  4s (mod r)
//            k  KMACXOF256(s, m, 448, “N”); k  4k (mod r)
//            U  k*G;
//            h  KMACXOF256(Ux, m, 448, “T”); z  (k – hs) mod r
//            signature: (h, z)
            System.out.println("Whats the file you would like to generate a signature for? {FileName}.txt");
            String fileName = scanner.nextLine();
            System.out.println("Whats the password you would like to generate the signature under?");
            String pw = scanner.nextLine();

            String fullFile = "";
            try {
                Scanner sc = new Scanner(new File(fileName));
                while (sc.hasNextLine()) {
                    String i = sc.nextLine();
                    // System.out.println(i);
                    fullFile = fullFile + i + "\n";
                }
                fullFile = fullFile.substring(0, fullFile.length() - 1);
                sc.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            byte[] message = fullFile.getBytes();

            int outputLength = 448;
            byte[] sBytes = cipherpol.KMACXOF256(pw.getBytes(), "".getBytes(), outputLength, "SK".getBytes());
            BigInteger s = new BigInteger(sBytes).multiply(BigInteger.valueOf(4)).mod(Curved.R_448);;
            byte[] kBytes = cipherpol.KMACXOF256(s.toByteArray(), message, outputLength, "N".getBytes());
            BigInteger k = new BigInteger(kBytes).multiply(BigInteger.valueOf(4)).mod(Curved.R_448);;

            Curved g = new Curved(); g.CurvedG();
            Curved U = g.scalarMultiply(k);

            BigInteger h = new BigInteger(cipherpol.KMACXOF256(U.x.toByteArray(), message, 448, "T".getBytes())).mod(Curved.R_448);
            BigInteger z = (k.subtract(h.multiply(s))).mod(Curved.R_448);

            saveSignature(fileName.replace(".txt", "_sign.txt"), h, z);

        } else if (choice == 5) {
            // Verifying a signature U = z*G + h*V
            // Accept if KMACXOF256(Ux, m, 448, "T") = h;
            System.out.println("What file are you trying to verify? {fileName}.txt");
            String fileName = scanner.nextLine();
            String fullFile = "";
            try {
                Scanner sc = new Scanner(new File(fileName));
                while (sc.hasNextLine()) {
                    String i = sc.nextLine();
                    // System.out.println(i);
                    fullFile = fullFile + i + "\n";
                }
                fullFile = fullFile.substring(0, fullFile.length() - 1);
                sc.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            byte[] message = fullFile.getBytes();

            String hz = loadSignature(fileName.replace(".txt", "_sign.txt"));
            String hStr = hz.split("\n")[0];
            BigInteger h = new BigInteger(hStr);

            String zStr = hz.split("\n")[1];
            BigInteger z = new BigInteger(zStr);

            Curved V = readFileCurve(fileName.replace(".txt", "_public.txt"));

            Curved g = new Curved(); g.CurvedG();
            Curved U = g.scalarMultiply(z).add(V.scalarMultiply(h));

            BigInteger hTest = new BigInteger(cipherpol.KMACXOF256(U.x.toByteArray(), message, 448, "T".getBytes())).mod(Curved.R_448);;

            if (h.equals(hTest)) {
                System.out.println("The signature is valid");
            } else {
                System.out.println("h is \n" + h);
                System.out.println("hTest is \n" + hTest);
                System.out.println("The signature is invalid");
            }
        } else {
            System.out.println("The input was invalid");
            scanner.close();
            System.exit(1);
        }
        scanner.close(); // Close the scanner after it's not being used anymore
    }

    public static void generateKeyPair(String fileName, String pw) {
        int outputLength = 448;
        byte[] sBytes = cipherpol.KMACXOF256(pw.getBytes(), "".getBytes(), outputLength, "SK".getBytes());
        BigInteger s = new BigInteger(sBytes);
        s = s.multiply(BigInteger.valueOf(4)).mod(Curved.R_448);;
        Curved g = new Curved(); g.CurvedG();
        Curved V = g.scalarMultiply(s);

        System.out.println("The private key is \n" + pw);
        System.out.println("Public Key is ");
        System.out.println(V);

        saveFileCurve(fileName.replace(".txt", "_public.txt"), V);
    }

    /** Check if the user wants to read from a file.
     *
     * @param scanner Scanner used to get user input
     * @return true if the user wants to read from a file and false if the user would like to use the console
     */
    public static boolean fromFile(Scanner scanner) {
        System.out.println("Would you like to read from a file? (Y/N)");
        String s = scanner.nextLine().toLowerCase();
        return s.equals("y") || s.equals("yes");
    }

    /** Method to save bytes as hex to a file. Pass in the name and data and it will save it for you.
     *
     * @param fileName The name for the file to be saved as
     * @param data The data to save to the file in terms of a byte array.
     */
    public static void saveFile(String fileName, byte[] data) {
        try {
            System.out.println("The file name " + fileName);
            FileWriter myWriter = new FileWriter(fileName);
            myWriter.write( bytesToHexString(data) );
            myWriter.close();
            System.out.println("Successfully wrote to the file.");
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }
    }

    public static byte[] readFile(String fileName) {
        String fullFile = "";
        try {
            Scanner sc = new Scanner(new File(fileName));
            while (sc.hasNextLine()) {
                String i = sc.nextLine();
                // System.out.println(i);
                fullFile = fullFile + i + "\n";
            }
            fullFile = fullFile.substring(0, fullFile.length() - 1);
            sc.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        byte[] bytes = hexStringToBytes(fullFile);
        return bytes;
    }

    public static void saveSignature(String fileName, BigInteger h, BigInteger z) {
        try {
            System.out.println("The file name " + fileName);
            FileWriter myWriter = new FileWriter(fileName);

            String toWrite = h.toString() + "\n" + z.toString();

            myWriter.write( toWrite );
            myWriter.close();
            System.out.println("Successfully wrote to the file.");
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }
    }

    public static String loadSignature(String fileName) {
        String fullFile = "";
        String out = "";
        try {
            Scanner sc = new Scanner(new File(fileName));
            while (sc.hasNextLine()) {
                String i = sc.nextLine();
                // System.out.println(i);
                fullFile = fullFile + i + "\n";
            }
            fullFile = fullFile.substring(0, fullFile.length() - 1);
            out = fullFile;
            sc.close();
        } catch (Exception e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
            return null;
        }
        return out;
    }

    public static void saveFileCurve(String fileName, Curved curve) {
        try {
            System.out.println("The file name " + fileName);
            FileWriter myWriter = new FileWriter(fileName.replace(".txt", "_X.txt"));

            myWriter.write(curve.x.toString());

            myWriter.close();
            System.out.println("Successfully wrote to the X file.");

            myWriter = new FileWriter(fileName.replace(".txt", "_Y.txt"));

            myWriter.write(curve.y.toString());

            myWriter.close();
            System.out.println("Successfully wrote to the Y file.");
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }
    }

    public static Curved readFileCurve(String fileName) {
        String fullFile = "";
        Curved out = new Curved();
        try {

            Scanner sc = new Scanner(new File(fileName.replace(".txt", "_X.txt")));
            while (sc.hasNextLine()) {
                String i = sc.nextLine();
                // System.out.println(i);
                fullFile = fullFile + i + "\n";
            }
            fullFile = fullFile.substring(0, fullFile.length() - 1);
            out.x = new BigInteger(fullFile);
            sc.close();
            fullFile = "";

            sc = new Scanner(new File(fileName.replace(".txt", "_Y.txt")));
            while (sc.hasNextLine()) {
                String i = sc.nextLine();
                // System.out.println(i);
                fullFile = fullFile + i + "\n";
            }
            fullFile = fullFile.substring(0, fullFile.length() - 1);
            out.y = new BigInteger(fullFile);
            sc.close();
        } catch (Exception e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
            return null;
        }
        return out;
    }

    /** Convert a byte array to a hex string(String with numbers from 1-f) and output it.
     *
     * @param byteArray The byte array to convert to hex
     */
    public static void toHexString(byte[] byteArray) {
        for (byte b: byteArray) {
            if (((int)(b & 0xFF)) < 16) {
                System.out.print("0");
            }
            System.out.print(Integer.toHexString(b & 0xFF) + " ");
        }
        System.out.println();
    }

    /** Convert a hex string into a byte array.
     *
     * https://stackoverflow.com/a/140861
     *
     * @param hex The hex string to convert into bytes
     * @return The hex string as a byte array
     */
    public static byte[] hexStringToBytes(String hex) {
        hex = hex.length() % 2 == 1 ? hex + 0x0 : hex;  //handle odd numbered strings
        byte[] bytes = new byte[hex.length() / 2];      //every 2 chars from hex represents 1 byte
        for (int i = 0; i < hex.length(); i += 2) {     //Convert 1st char to int, shift left 4 bits,
            // logical OR with next int, receive byte.
            bytes[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                + Character.digit(hex.charAt(i+1), 16));
        }
        return bytes;
    }

    /** Convert a byte array into a hex string.
     *
     * http://www.java2s.com/example/java-utility-method/byte-array-to-hex-string/bytestohexstring-final-byte-bytes-924fa.html
     *
     * @param bytes The byte array to convert
     * @return The hex String derived from the byte array
     */
    public static String bytesToHexString(final byte[] bytes) {
        final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();
        // every 2 chars represents 1 byte
        final char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            //mask with 0xFF to ensure valid int range
            final int v = bytes[i] & 0xFF;
            //logical unsigned shift right (no negative indices for HEX_ARRAY)
            hexChars[i * 2] = HEX_ARRAY[v >>> 4];
            hexChars[i * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Concatenates two byte arrays into one.
     * https://stackoverflow.com/questions/5683486/how-to-combine-two-byte-arrays
     *
     * @param firstArray  the first byte array to concatenate
     * @param secondArray the second byte array to concatenate
     * @return a new byte array containing all elements of the first array followed
     *         by all elements of the second array
     */
    public static byte[] concat(byte[] firstArray, byte[] secondArray) {
        int firstLength = firstArray.length;
        int secondLength = secondArray.length;

        byte[] combinedArray = new byte[firstLength + secondLength];

        System.arraycopy(firstArray, 0, combinedArray, 0, firstLength);
        System.arraycopy(secondArray, 0, combinedArray, firstLength, secondLength);

        return combinedArray;
    }

    /** Perform a Xor operation on two different byte arrays and return the XOR. This assumes that the lengths of
     * the two byte arrays are the same.
     *
     * @param bFirst First byte array to XOR.
     * @param bSecond Second byte array to XOR.
     * @return The byte array which is returned when you XOR the byte arrays passed in.
     */
    public static byte[] XOR(byte[] bFirst, byte[] bSecond) {
        byte[] out = new byte[bFirst.length];
        int i = 0;
        for (byte b : bFirst) {
            out[i] = (byte) (b ^ bSecond[i++]);
        }
        return out;
    }


    public static void encrypt(String fileName) {
        Random random = new Random();
        BigInteger r = Curved.R_448;  // Assuming R_448 is the order of the curve
        BigInteger k = new BigInteger(448, random).multiply(BigInteger.valueOf(4)).mod(r);

        Curved V = readFileCurve(fileName.replace(".txt", "_public.txt"));

        // W = k * V, Z = k * G (where G is the base point)
        Curved W = V.scalarMultiply(k);
        Curved G = new Curved();  // Assuming the constructor sets G as the base point
        G.CurvedG();
        Curved Z = G.scalarMultiply(k);

        // (ka || ke) <- KMACXOF256(Wx, “”, 2×448, “PK”)
        byte[] ka_ke = cipherpol.KMACXOF256(W.x.toByteArray(), "".getBytes(), 2 * 448, "PK".getBytes());
        byte[] ka = new byte[448 / 8];
        byte[] ke = new byte[448 / 8];
        System.arraycopy(ka_ke, 0, ka, 0, ka.length);
        System.arraycopy(ka_ke, ka.length, ke, 0, ke.length);

        String fullFile = "";
        try {
            Scanner sc = new Scanner(new File(fileName));
            while (sc.hasNextLine()) {
                String i = sc.nextLine();
                // System.out.println(i);
                fullFile = fullFile + i + "\n";
            }
            fullFile = fullFile.substring(0, fullFile.length() - 1);
            sc.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        byte[] message = fullFile.getBytes();

        // c <- KMACXOF256(ke, “”, |m|, “PKE”) XOR m
        byte[] c = cipherpol.KMACXOF256(ke, "".getBytes(), message.length * 8, "PKE".getBytes());
        for (int i = 0; i < message.length; i++) {
            c[i] ^= message[i];
        }

        // t <- KMACXOF256(ka, m, 448, “PKA”)
        byte[] t = cipherpol.KMACXOF256(ka, message, 448, "PKA".getBytes());

        System.out.println("z, c and t is");
        System.out.println(Z);
        toHexString(c);
        toHexString(t);

        saveFileCurve(fileName.replace(".txt", "_Z.txt"), Z);
        saveFile(fileName.replace(".txt", "_c.txt"), c);
        saveFile(fileName.replace(".txt", "_t.txt"), t);
    }

    public static void decrypt(String fileName, String pw) {
        Curved Z = readFileCurve(fileName.replace(".txt", "_Z.txt"));
        byte[] c = readFile(fileName.replace(".txt", "_c.txt"));
        byte[] t = readFile(fileName.replace(".txt", "_t.txt"));

        System.out.println("z, c and t is");
        System.out.println(Z);
        toHexString(c);
        toHexString(t);

        BigInteger r = Curved.R_448; // Order of the curve

        // s <- KMACXOF256(pw, “”, 448, “SK”); s <-  4s mod r
        byte[] sBytes = cipherpol.KMACXOF256(pw.getBytes(), "".getBytes(), 448, "SK".getBytes());
        BigInteger s = new BigInteger(sBytes).multiply(BigInteger.valueOf(4)).mod(r);

        // W <- sZ
        Curved W = Z.scalarMultiply(s);

        // (ka || ke) <- KMACXOF256(Wx, “”, 2×448, “PK”)
        byte[] ka_ke = cipherpol.KMACXOF256(W.x.toByteArray(), "".getBytes(), 2*448, "PK".getBytes());
        byte[] ka = new byte[448 / 8];
        byte[] ke = new byte[448 / 8];
        System.arraycopy(ka_ke, 0, ka, 0, ka.length);
        System.arraycopy(ka_ke, ka.length, ke, 0, ke.length);

        // m <- KMACXOF256(ke, “”, |c|, “PKE”) XOR c
        byte[] m = cipherpol.KMACXOF256(ke, new byte[]{}, c.length * 8, "PKE".getBytes());
        for (int i = 0; i < c.length; i++) {
            m[i] ^= c[i];
        }

        // t’ <- KMACXOF256(ka, m, 448, “PKA”)
        byte[] tPrime = cipherpol.KMACXOF256(ka, m, 448, "PKA".getBytes());

        // accept if, and only if, t’ = t
        if (Arrays.equals(tPrime, t)) {
            saveFile(fileName.replace(".txt", "_dec.txt"), m);
        } else {
            System.out.println("Something went wrong, t and tPrime");
            toHexString(t);
            toHexString(tPrime);
        }
    }

}