import java.util.Arrays;

public class cipherpol {
    /**
     * Keccak round constants for use in the iota step of the Keccak hashing
     * algorithm.
     * 
     * https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
     * 
     */
    private static final long[] KECCAKF_ROUND_CONSTANTS = {
        0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL, 0x8000000080008000L,
        0x000000000000808bL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
        0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
        0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L, 0x8000000000008003L,
        0x8000000000008002L, 0x8000000000000080L, 0x000000000000800aL, 0x800000008000000aL,
        0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    /**
     * Keccak rotation values that specify the rotation offsets in the rho step.
     * 
     * https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
     * 
     */
    private static final int[] KECCAKF_ROTATION = {
        1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
        27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    };

    /**
     * Keccak permutation indices specifying the order in which to access state
     * array elements.
     * 
     * https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
     * 
     */
    private static final int[] KECCAKF_PERMUTATION = {
        10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
    };

    /**
     * Performs a left rotation on a 64-bit long value by a given shift amount.
     *
     * https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
     * 
     * @param value       The value to rotate.
     * @param shiftAmount The number of positions to rotate the value.
     * @return The rotated value.
     */
    private static long rotateLeft64(long value, int shiftAmount) {
        // Normalize shift to avoid overflow issues
        shiftAmount = shiftAmount & 63;
        return (value << shiftAmount) | (value >>> (64 - shiftAmount));
    }

    /**
     * Performs the theta step in the Keccak hashing algorithm, mixing column
     * parity.
     *
     * https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
     * 
     * @param inputState The Keccak state array.
     */
    private static long[] theta(long[] inputState) {
        long[] outputState = new long[25];
        long[] C = new long[5];

        for (int i = 0; i < 5; i++) {
            C[i] = inputState[i];
            for (int j = 1; j < 5; j++) {
                C[i] ^= inputState[i + 5 * j];
            }
        }

        for (int i = 0; i < 5; i++) {
            long d = C[(i + 4) % 5] ^ rotateLeft64(C[(i + 1) % 5], 1);
            for (int j = 0; j < 5; j++) {
                outputState[i + 5 * j] = inputState[i + 5 * j] ^ d;
            }
        }

        return outputState;
    }

    /**
     * Performs the rho and phi steps in the Keccak algorithm, rotating and
     * permuting the state array.
     *
     * https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
     * 
     * @param inputState The Keccak state array.
     */
    private static long[] rhoPhi(long[] inputState) {
        long[] outputState = new long[25];
        outputState[0] = inputState[0];

        long current = inputState[1];
        for (int i = 0; i < 24; i++) {
            int index = KECCAKF_PERMUTATION[i];
            long temp = inputState[index];
            outputState[index] = rotateLeft64(current, KECCAKF_ROTATION[i]);
            current = temp;
        }
        return outputState;
    }

    /**
     * Performs the chi step in the Keccak hashing algorithm.
     *
     * https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
     * 
     * @param inputState The Keccak state array.
     */
    private static long[] chi(long[] inputState) {
        long[] outputState = new long[25];
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                int index = i + 5 * j;
                outputState[index] = inputState[index] ^ (~inputState[(i + 1) % 5 + 5 * j] & inputState[(i + 2) % 5 + 5 * j]);
            }
        }
        return outputState;
    }

    /**
     * Performs the iota step in the Keccak hashing algorithm, modifying the state
     * with a round constant.
     *
     * https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
     * 
     * @param state      The Keccak state array.
     * @param roundIndex The index of the current round.
     */
    private static long[] iota(long[] state, int roundIndex) {
        state[0] ^= KECCAKF_ROUND_CONSTANTS[roundIndex];
        return state;
    }

    /**
     * SHAKE256 function generating a hash of specified length.
     *
     * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
     * 
     * @param x Input data for hashing.
     * @param l Desired output length in bits.
     * @param n Function name for customization, empty if not used.
     * @param s Custom string for customization, empty if not used.
     * @return Hashed output as byte array.
     */
    public static byte[] cSHAKE256(byte[] x, int l, byte[] n, byte[] s) {
        byte[] encodedN = encodeString(n); // Assume this function encodes the string as needed.
        byte[] encodedS = encodeString(s); // Assume this function encodes the custom string.
    
        // Concatenate the encoded function name (n) and custom string (s) and pad them.
        byte[] paddedNandS = bytePad(concat(encodedN, encodedS), 136); // 'bytePad' should add padding according to cSHAKE spec.
        // Append the input data (x) and domain separation byte.
        byte[] formattedX = concat(concat(paddedNandS, x), new byte[]{0x04});
    
        // The 'rate' for cSHAKE256 is 1088 bits (136 bytes), as its capacity is 512 bits and the width is 1600 bits.
        int rate = 1088; // cSHAKE256 uses a rate of 1088 bits, which is 136 bytes.
        int capacity = 512;
    
        // Absorb the input into the Keccak state.
        long[] state = Absorb(formattedX, rate, capacity);
    
        // Squeeze out the output of the desired bit length (l) from the Keccak state.
        return Squeeze(state, l, rate);
    }

    /**
     * Computes KMACXOF256, a keyed hash function for message authentication.
     * 
     * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
     * 
     * TCSS 487 - KMACXOF256.pdf
     * 
     * @param n The key for KMAC.
     * @param x The input message to be MACed.
     * @param l The desired output length in bits.
     * @param s The customization string.
     * @return Computed KMAC as byte array.
     */
    public static byte[] KMACXOF256(byte[] n, byte[] x, int l, byte[] s) {
        byte[] padded = bytePad(encodeString(n), 136); 
        byte[] encodedZero = rightEncode(0); 
        byte[] combinedX = concat(concat(padded, x), encodedZero); 
        byte[] functionName = "KMAC".getBytes(); 
        
        return cSHAKE256(combinedX, l, functionName, s); 
    }
    
    /**
     * Encodes the given integer x into an array of bytes, with the first byte
     * indicating the length of the encoded integer in additional bytes.
     * 
     * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
     * https://stackoverflow.com/questions/9655181/java-convert-a-byte-array-to-a-hex-string
     * https://stackoverflow.com/questions/37963917/convert-string-to-from-byte-array-without-encoding
     * 
     * @param x The integer to encode.
     * @return An array where the first byte is the length of the following bytes
     *         that represent the integer x.
     */
    private static byte[] leftEncode(int x) {
        int byteLength = 1;
        while ((1 << (8 * byteLength)) <= x) {
            byteLength++;
        }
    
        byte[] encodedBytes = new byte[byteLength + 1];
        for (int i = byteLength; i > 0; i--) {
            encodedBytes[i] = (byte) (x & 0xFF);
            x >>>= 8;
        }
    
        encodedBytes[0] = (byte) byteLength;
        return encodedBytes;
    }

    /**
     * Encodes the given integer x into an array of bytes in reverse order, with the
     * last byte
     * indicating the original byte length of x.
     * 
     * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
     * https://stackoverflow.com/questions/9655181/java-convert-a-byte-array-to-a-hex-string
     * https://stackoverflow.com/questions/37963917/convert-string-to-from-byte-array-without-encoding
     * 
     * @param x The integer to encode.
     * @return An array of bytes representing the integer in reverse order with the
     *         last byte as its original length.
     */
    private static byte[] rightEncode(int x) {
        int byteLength = 1;
        while ((1 << (8 * byteLength)) <= x) {
            byteLength++;
        }
    
        byte[] encodedBytes = new byte[byteLength + 1];
        for (int i = 0; i < byteLength - 1; i++) {
            encodedBytes[i] = (byte) (x & 0xFF);
            x >>>= 8;
        }
        encodedBytes[byteLength] = (byte) byteLength;
        return encodedBytes;
    }

    /**
     * Encodes a string's byte array representation by prefixing it with its bit
     * length.
     *
     * @param input The byte array representing the string to encode.
     * @return A concatenated array containing the bit length of input and the input
     *         itself.
     */
    private static byte[] encodeString(byte[] input) {
        if (input == null || input.length == 0) {
            return leftEncode(0);
        }
        
        int bitLength = input.length * 8;  // Use int instead of BigInteger
        return concat(leftEncode(bitLength), input);
    }

    /**
     * Pads the input array X to a length that is a multiple of the block size 'w'.
     * 
     * TCSS 487 - KMACXOF256.pdf
     * 
     * @param X The input byte array to be padded.
     * @param w The block size to pad to a multiple of.
     * @return A new byte array containing the original array 'X' padded with 'w'.
     */
    private static byte[] bytePad(byte[] X, int w) {
        // Validity Conditions: w > 0
        assert w > 0;
        // 1. z = left_encode(w) || X.
        byte[] wenc = leftEncode(w);  // <-- Changed this line
        byte[] z = new byte[w*((wenc.length + X.length + w - 1)/w)];
        // NB: z.length is the smallest multiple of w that fits wenc.length + X.length
        System.arraycopy(wenc, 0, z, 0, wenc.length);
        System.arraycopy(X, 0, z, wenc.length, X.length);
        for (int i = wenc.length + X.length; i < z.length; i++) {
            z[i] = (byte)0;
        }
        return z;
    }

    /**
     * Absorbs the input bytes into the Keccak state array after padding.
     *
     * @param in  The input byte array to be absorbed.
     * @param rate The bit length used to determine output length.
     * @param capacity    The capacity, subtracted from the block size to determine the
     *               rate.
     * @return The updated Keccak state array after absorption.
     */
    public static long[] Absorb(byte[] in, int rate, int capacity) {
        byte[] padded = padTen(rate, in);
        int lanes = rate / 64;
        long[] state = new long[25];

        for (int i = 0; i < padded.length; i += rate / 8) {
            for (int j = 0; j < lanes; j++) {
                long data = 0;
                for (int b = 0; b < 8; b++) {
                    data |= ((long) padded[i + j * 8 + b] & 0xFF) << (8 * b);
                }
                state[j] ^= data;
            }
            state = keccak(state, 1600, 24); // keccakp to be implemented or used from existing library.
        }
        return state;
    }

    /**
     * Extracts a byte array of specified length from the Keccak state.
     *
     * @param state  The state from which bytes are to be extracted.
     * @param bitLen The length of output in bits.
     * @param rate    The capacity part of the state, determining the rate.
     * @return Extracted byte array of length 'bitLen/8'.
     */
    public static byte[] Squeeze(long[] state, int bitLen, int rate) {
        // Calculate the output length in bytes.
        int outputBytes = (bitLen + 7) / 8;
        byte[] out = new byte[outputBytes];
        int outputProduced = 0; // Counter for the number of bytes produced.
        int byteRate = rate / 8; // Calculate the rate in bytes.

        // Loop to produce output bytes.
        while (outputProduced < outputBytes) {
            int bytePos = 0; // Position in the temporary output for the current state.
            byte[] temporary = new byte[byteRate]; // Temporary byte array for the current squeezed data.

            // Convert state to byte array (equivalent to stateToByteArray logic but respects the rate limit).
            for (int i = 0; i < state.length && bytePos < byteRate; i++) {
                for (int offset = 0; offset < 8 && bytePos < byteRate; offset++) {
                    temporary[bytePos++] = (byte) ((state[i] >>> (8 * offset)) & 0xFF);
                }
            }

            // Copy the squeezed bytes to the output array.
            int amountToCopy = Math.min(byteRate, outputBytes - outputProduced);
            System.arraycopy(temporary, 0, out, outputProduced, amountToCopy);
            outputProduced += amountToCopy;

            // Check if more output is needed and perform the permutation if necessary.
            if (outputProduced < outputBytes) {
                state = keccak(state, 1600, 24); // Perform the permutation to refresh the state.
            }
        }

        // Mask off excess bits if bit length is not a multiple of 8.
        if (bitLen % 8 != 0) {
            out[outputBytes - 1] &= (1 << (bitLen % 8)) - 1;
        }

        return out; // Return the final output array.
    }

    /**
     * Pads the input data as per the "pad10*1" padding scheme.
     * This padding is required for Keccak-based constructions to fill the input data to a full block.
     * It adds between 1 and `rate` bits, all zeroes except for the first and last bits of the padding, which are 1.
     *
     * https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
     *
     * @param rate The block size (rate of the sponge function) in bits.
     * @param in The input data to be padded.
     * @return A new array containing the original data with padding applied as necessary.
     */
    private static byte[] padTen(int rate, byte[] in) {
        // Calculate the number of padding bytes needed.
        int bytesToPad = (rate / 8) - (in.length % (rate / 8));

        // If no padding is needed, return the input array as is.
        if (bytesToPad == rate / 8) {
            return in;
        }

        // Create a new array with the correct size for the input plus padding.
        byte[] padded = Arrays.copyOf(in, in.length + bytesToPad);

        // Add the "1" bit followed by all "0" bits, ending with another "1" bit.
        padded[padded.length - 1] = (byte) 0x80; // 0x80 represents the hex value for the "10000000" bit pattern.

        return padded; // Return the padded array.
    }


    
    /**
     * Applies the Keccak permutation function.
     *
     * @param stateIn  The initial state for permutation.
     * @param bitLen The bit length of the state.
     * @param rounds The number of permutation rounds.
     * @return The state array after permutation.
     */
    private static long[] keccak(long[] stateIn, int bitLen, int rounds) {
        long[] stateOut = stateIn;
        int l = floorLog(bitLen/25);
        for (int i = 12 + 2*l - rounds; i < 12 + 2*l; i++) {
            stateOut = iota(chi(rhoPhi(theta(stateOut))), i);
        }
        return stateOut;
    }

    /**
     * Computes the floor log base 2 of 'n', equal to the position of the highest bit set.
     *
     * https://stackoverflow.com/questions/48933596/how-to-use-loops-to-find-the-exponent-of-a-base-that-produces-an-argument
     *
     * @param n Positive integer to compute log base 2 for.
     * @return Floor of log base 2 of 'n'.
     */
    private static int floorLog(int n) {
        int exponent = 0;
    
        while (n > 1) {
            n >>= 1;
            exponent++;
        }

        return exponent;
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
        // Determine the length of the first array
        int firstLength = firstArray.length;
        // Determine the length of the second array
        int secondLength = secondArray.length;

        // Create a new array large enough to hold both arrays
        byte[] combinedArray = new byte[firstLength + secondLength];

        // Copy the first array into the start of the combined array
        System.arraycopy(firstArray, 0, combinedArray, 0, firstLength);
        // Copy the second array into the combined array, immediately after the first
        // array
        System.arraycopy(secondArray, 0, combinedArray, firstLength, secondLength);

        // Return the new, combined array
        return combinedArray;
    }
}