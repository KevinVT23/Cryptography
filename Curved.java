import java.math.BigInteger;
import java.util.Random;

public class Curved {
    // Constants for the Ed448-Goldilocks curve
    private static final BigInteger P = BigInteger.valueOf(2).pow(448).subtract(BigInteger.valueOf(2).pow(224)).subtract(BigInteger.ONE);

    public static final BigInteger D_448 = BigInteger.valueOf(-39081);
    public static final BigInteger P_448 = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);
    public static final BigInteger R_448 = new BigInteger("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3", 16);


    // Point coordinates
    public BigInteger x;
    public BigInteger y;

    // Constructor for the neutral element O
    public Curved() {
        this.x = BigInteger.ZERO;
        this.y = BigInteger.ONE;
    }

    // Constructor for a given point (x, y)
    public Curved(BigInteger x, BigInteger y) {
        this.x = x.mod(P);
        this.y = y.mod(P);
    }


    public Curved(BigInteger y, boolean lsbX) {
        this.y = y.mod(P_448);
        // x is even so least sig bit is 0
        // x is found from x = +-sqrt((1-y^2)/(1+39081y^2))modp;

        // 1-y^2
        BigInteger f = BigInteger.ONE.subtract(y.pow(2));

        // 1+39081y^2
        BigInteger s = BigInteger.ONE.add(BigInteger.valueOf(39081).multiply(y.pow(2)));

        // inverse of (1+39081y^2)
        BigInteger sInv = s.modInverse(P_448);

        this.x = sqrt(f.multiply(sInv), (P_448), lsbX);
    }

    public void CurvedG() {
        this.y = BigInteger.valueOf(-3).mod(P_448);

        // x is even so least sig bit is 0
        // x is found from x = +-sqrt((1-y^2)/(1+39081y^2))modp;

        // 1-y^2
        BigInteger f = BigInteger.ONE.subtract(y.pow(2));

        // 1+39081y^2
        BigInteger s = BigInteger.ONE.add(BigInteger.valueOf(39081).multiply(y.pow(2)));

        // inverse of (1+39081y^2)
        BigInteger sInv = s.modInverse(P_448);

        this.x = sqrt(f.multiply(sInv), (P_448), false);
    }

    public static Curved sum(Curved p1, Curved p2) {
        // Edwards curve point addition
        BigInteger multAll = D_448.multiply(p1.x).multiply(p2.x).multiply(p1.y).multiply(p2.y);

        BigInteger n1 = (p1.x.multiply(p2.y)).add(p1.y.multiply(p2.x));
        BigInteger d1 = BigInteger.ONE.add(multAll);

        BigInteger n2 = (p1.y.multiply(p2.y)).subtract(p1.x.multiply(p2.x));
        BigInteger d2 = BigInteger.ONE.subtract(multAll);

        BigInteger d1Inv = d1.modInverse(P_448);
        BigInteger d2Inv = d2.modInverse(P_448);

        BigInteger x = n1.multiply(d1Inv).mod(P_448);
        BigInteger y = n2.multiply(d2Inv).mod(P_448);

        return new Curved(x, y);
    }

    public Curved add(Curved other) {
        return sum(this, other);
    }

    public Curved opposite() {
        return new Curved(P_448.subtract(this.x), this.y);
    }

    public boolean equals(Curved other) {
        return (this.x.equals(other.x) && this.y.equals(other.y));
    }

    public Curved scalarMultiply(BigInteger s) {
        if (s.equals(BigInteger.ZERO)) { return new Curved();}

        String sBinary = s.toString(2);
        Curved V = this;
        for (int i = 1; i < sBinary.length(); i++) {
            V = V.add(V);
            if (sBinary.charAt(i) == '1') {
                V = V.add(this);
            }
        }
        return V;
    }

/**
* Compute a square root of v mod p with a specified least-significant bit
* if such a root exists.
*
* @param v the radicand.
* @param p the modulus (must satisfy p mod 4 = 3).
* @param lsb desired least significant bit (true: 1, false: 0).
* @return a square root r of v mod p with r mod 2 = 1 iff lsb = true
* if such a root exists, otherwise null.
*/
    public static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
        assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
        if (v.signum() == 0) {
        return BigInteger.ZERO;
        }
        BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
        if (r.testBit(0) != lsb) {
        r = p.subtract(r); // correct the lsb
        }
        return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
    }

    @Override
    public String toString() {
        return "(x: " +this.x.toString() + ", " + "y: " + this.y.toString() + ")";
    }

    public static void tests() {
        Curved g = new Curved();
        g.CurvedG();
        System.out.println("Generator point is ");
        System.out.println(g);
        System.out.println("Test multiply by 0\n" + g.scalarMultiply(BigInteger.ZERO));
        System.out.println("Test multiply by 1\n" + g.scalarMultiply(BigInteger.ONE));

        System.out.println("Test adding opposite\n" + g.add(g.opposite()));

        System.out.println("Test adding a point to itself and multiplying by two\n" + g.add(g) + "\n" + g.scalarMultiply(BigInteger.TWO));

        System.out.println("Test multiplying by 4 and multiplying by 2 twice\n" + g.scalarMultiply(BigInteger.valueOf(4))
                + "\n" + g.scalarMultiply(BigInteger.TWO).scalarMultiply(BigInteger.TWO));
        System.out.println("Test multiplying by r should result in 0\n" + g.scalarMultiply(R_448));


        Random random = new Random();


        for (int i = 1; i <= 100; i++) {
            BigInteger k = BigInteger.valueOf(random.nextInt());
            k = k.abs();
            BigInteger l = BigInteger.valueOf(random.nextInt());
            l = l.abs();
            BigInteger m = BigInteger.valueOf(random.nextInt());
            m = m.abs();

            if (!g.scalarMultiply(k).equals(g.scalarMultiply(k.mod(R_448)))) {
                System.out.println("G*k = G*kmodr broke!");
                System.out.println("k is " + k);
                System.out.println(g.scalarMultiply(k));
                System.out.println(g.scalarMultiply(k.mod(R_448)));
            } //else {
//                System.out.println("G*k = G*kmodr worked!");
//                System.out.println("k is " + k);
//                System.out.println(g.scalarMultiply(k));
//                System.out.println(g.scalarMultiply(k.mod(R_448)));
//            }
            if (!g.scalarMultiply(k.add(BigInteger.ONE)).equals(g.scalarMultiply(k).add(g))) {
                System.out.println("G*(k+1) = G*k+G broke!");
                System.out.println("k is " + k);
                System.out.println(g.scalarMultiply(k.add(BigInteger.ONE)));
                System.out.println(g.scalarMultiply(k).add(g));
            } //else {
//                System.out.println("G*(k+1) = G*k+G worked!");
//                System.out.println("k is " + k);
//                System.out.println(g.scalarMultiply(k.add(BigInteger.ONE)));
//                System.out.println(g.scalarMultiply(k).add(g));
//            }
            if (!g.scalarMultiply(k.add(l)).equals(g.scalarMultiply(k).add(g.scalarMultiply(l)))) {
                System.out.println("G*(k+l) = G*k+G*l broke!");
                System.out.println(k);
                System.out.println(l);

            } //else {
//                System.out.println("G*(k+l) = G*k+G*l worked!");
//                System.out.println(k);
//                System.out.println(l);
//            }
            if (!(g.scalarMultiply(l).scalarMultiply(k).equals(g.scalarMultiply(k).scalarMultiply(l))
                    && g.scalarMultiply(l).scalarMultiply(k).equals(g.scalarMultiply((k.multiply(l).mod(R_448)))))) {
                System.out.println("G*(k+1) = G*k+G broke!");
                System.out.println(k);
                System.out.println(l);
            } //else {
//                System.out.println("G*(k+1) = G*k+G worked!");
//                System.out.println(k);
//                System.out.println(l);
//            }
                if (!(
                        g.scalarMultiply(k).add(g.scalarMultiply(l).add(g.scalarMultiply(m))).equals(
                                (g.scalarMultiply(k).add(g.scalarMultiply(l))).add(g.scalarMultiply(m)))
                )) {
                    System.out.println("k*G +(l*G+m*G) = (k*G+l*G)+m*G broke!");
                    System.out.println(k);
                    System.out.println(l);
                    System.out.println(m);
                } //else {
//                System.out.println("k*G +(l*G+m*G) = (k*G+l*G)+m*G worked!");
//                System.out.println(k);
//                System.out.println(l);
//                System.out.println(m);
//            }
        }
    }
}
