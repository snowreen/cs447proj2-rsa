import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;

public class Main {

    private static List<String> inputList = null;
    private static List<String> chunkedInputList = null;
    private static Random random = new Random();
    private static BigInteger randomNumbersMultiplicationResult = null;
    private static BigInteger publicKeyExponent = null;
    private static BigInteger privateKeyExponent = null;

    public static void main(String[] args) {

        //Key Generation (Public key and secret key both might be different every time the application runs)
        keyGeneration();

        Scanner scanner = new Scanner(System.in);

        //Encryption Part
        while(true) {
            System.out.println("Enter the file name with FULL PATH to Encrypt: ");
            String fileName = scanner.next();
            try {
                readTextFile(fileName);
            } catch (IOException e) {
                System.out.println("Invalid file path !!! Try Again !!!");
                continue;
            }
            String encryptedMsg = encryptWholeMessage();
            System.out.println("\nEncrypted Text is below: \n");
            System.out.println(encryptedMsg);
            try {
                writeMessage(encryptedMsg, "encrypted-msg.txt");
            } catch (IOException e) {
                System.out.println("Cannot write into file !!! Try Again !!!");
                break;
            }
            break;
        }

        //Decryption Part
        while(true) {
            System.out.println("\nNow enter file name to decrypt already encrypted text (for example, encrypted-msg.txt): ");
            String encryptedFileName = scanner.next();
            try {
                readFileToDecrypt(encryptedFileName);
            } catch (IOException e) {
                System.out.println("Invalid file path !!! Try Again !!!");
                continue;
            }
            String decryptedMsg = decryptWholeMessage();
            System.out.println("\nDecrypted Text is below: \n");
            System.out.println(decryptedMsg);
            try {
                writeMessage(decryptedMsg, "decrypted-msg.txt");
            } catch (IOException e) {
                System.out.println("Cannot write into file !!! Try Again !!!");
                break;
            }
            break;
        }

    }

    //Write encrypted/decrypted message to a file
    private static void writeMessage(String msg, String fileName) throws IOException {
        BufferedWriter writer = null;
        try {
            writer = Files.newBufferedWriter(Paths.get(fileName));
            writer.write(msg);
            System.out.println("\nThis is also being written into "+ fileName+" file in the project folder where code is running.\n");
        } catch (IOException e) {
            throw e;
        } finally {
            if (writer != null) {
                try {
                    writer.close();
                } catch (IOException e) {
                    System.out.println("Failed closing file !!!");
                }
            }
        }
    }

    //Reading plain text file and creating chunks
    private static void readTextFile(String fileName) throws IOException {
        BufferedReader br = null;
        try {
            inputList = new ArrayList<>();
            chunkedInputList = new ArrayList<>();

            //Reading file and then putting each line into a list
            br = Files.newBufferedReader(Paths.get(fileName));
            inputList = br.lines().collect(Collectors.toList());

            //Now breaking each line into smaller chunk where each chunk length is 8, Using UTF-8 encoding so that each char will be 1 byte.
            //So each chunk size will be 8 byte (64 bit)
            for(String line : inputList) {
                int index = 0;
                while (index<line.length()) {
                    chunkedInputList.add(new String(line.substring(index, Math.min(index+8,line.length())).getBytes(), StandardCharsets.UTF_8));
                    index=index+8;
                }
                //Adding a new line after ending each line read from file
                chunkedInputList.add(new String("\n".getBytes(), StandardCharsets.UTF_8));
            }
        } catch (IOException e) {
            throw e;
        } finally {
            if (br != null) {
                br.close();
            }
        }
    }

    //Reading encrypted text file and creating chunks
    private static void readFileToDecrypt(String fileName) throws IOException {
        BufferedReader br = null;
        try {
            inputList = new ArrayList<>();
            chunkedInputList = new ArrayList<>();

            //Reading file and then putting each line into a list
            br = Files.newBufferedReader(Paths.get(fileName));
            inputList = br.lines().collect(Collectors.toList());

            //Now breaking each line into smaller chunk, for decryption each chunk length is 24, and using UTF-8 encoding so that each char will be 1 byte.
            //So each encrypted chunk size will be 24 byte (192 bit), because while encrypting we encrypted each chunk as 192 bit
            for(String line : inputList) {
                int index = 0;
                while (index<line.length()) {
                    chunkedInputList.add(new String(line.substring(index, Math.min(index+24,line.length())).getBytes(), StandardCharsets.UTF_8));
                    index=index+24;
                }
            }
        } catch (IOException e) {
            throw e;
        } finally {
            if (br != null) {
                br.close();
            }
        }
    }

    //Encrypting the whole message
    private static String encryptWholeMessage() {
        String encryptedMsg = new String("".getBytes(), StandardCharsets.UTF_8);
        for (String chunkedInputText : chunkedInputList) {
            String encryptedText = encryptChunk(chunkedInputText);
            encryptedMsg += encryptedText;
        }
        return encryptedMsg;
    }

    //Decrypting the whole message
    private static String decryptWholeMessage() {
        String decryptedMsg = new String("".getBytes(), StandardCharsets.UTF_8);
        for (String chunkedInputText : chunkedInputList) {
            decryptedMsg += decryptChunk(chunkedInputText);
        }
        return decryptedMsg;
    }

    //Encrypt a chunk of length 8 (64 bit in UTF-8), and encrypted chunk length is 24 (192 bit in UTF-8)
    private static String encryptChunk(String chunk) {
        //Using BigInteger to convert the chunk text into numbers and then perform calculation for RSA algorithm
        BigInteger numberRepresentationOfTextLine = new BigInteger(chunk.getBytes());

        //Using public key (n,e) where n=randomNumbersMultiplicationResult and e=publicKeyExponent,
        //calculating encryptedMsgInNumber which is ((numberRepresentationOfTextLine)^e % n)
        BigInteger encryptedMsgInNumber = numberRepresentationOfTextLine.modPow(publicKeyExponent, randomNumbersMultiplicationResult);

        //Now encoding the encryptedMsgInNumber bytes using Base64 encoder and then using UTF-8 converting to String
        String encryptedMsg = new String(Base64.getEncoder().encodeToString(encryptedMsgInNumber.toByteArray()).getBytes(), StandardCharsets.UTF_8);
        return encryptedMsg;
    }

    //Decrypt a chunk of length 24 (192 bit in UTF-8), and Decrypted chunk length is 8 (64 bit in UTF-8)
    private static String decryptChunk(String encryptedChunk) {
        //Decoding the encrypted chunk bytes using Base64 decoder and then converting to BigInteger
        BigInteger encryptedMsgNumberRepresentation = new BigInteger(Base64.getDecoder().decode(encryptedChunk.getBytes()));

        //Using private key(n, d) where n=randomNumbersMultiplicationResult and d=privateKeyExponent,
        //calculating decryptedMsgInNumber which is ((encryptedMsgNumberRepresentation)^d % n)
        BigInteger decryptedMsgInNumber = encryptedMsgNumberRepresentation.modPow(privateKeyExponent, randomNumbersMultiplicationResult);

        //Using UTF-8 converting to String
        String decryptedMsg = new String(decryptedMsgInNumber.toByteArray(), StandardCharsets.UTF_8);
        return decryptedMsg;
    }

    //This is the method for KeyGeneration.
    //This method will generate different public and secret key each time its being called,
    //Because we are getting 2 random primes of 64 bit each and then calculating the keys.
    private static void keyGeneration() {
        //This probablePrime method will give us a random prime with 64 bit length (chance of not getting a prime is very very very low, 2^-100)
        BigInteger randomPrime1 = BigInteger.probablePrime(64, random);
        BigInteger randomPrime2 = BigInteger.probablePrime(64, random);

        //This is will calculate, n = p*q where p=randomPrime1 and q=randomPrime2
        BigInteger multiplyRandomPrimes = randomPrime1.multiply(randomPrime2);

        //Now calculating eulersPhi which equals (p-1)(q-1) where p=randomPrime1 and q=randomPrime2
        BigInteger eulersPhi = (randomPrime1.subtract(BigInteger.ONE)).multiply(randomPrime2.subtract(BigInteger.ONE));

        //Getting a smaller prime than eulersPhi which has to be a relative prime,
        //Here making sure its relative prime by checking gcd(smallerPrime, eulersPhi) = 1
        //If not relative prime, then trying a new random number
        BigInteger smallRelativePrime = BigInteger.probablePrime(16, random);
        while (!eulersPhi.gcd(smallRelativePrime).equals(BigInteger.ONE)) {
            smallRelativePrime = BigInteger.probablePrime(16, random);
        }

        publicKeyExponent = smallRelativePrime;
        randomNumbersMultiplicationResult = multiplyRandomPrimes;

        //Now calculating private key/secret key exponent by doing (e mod inverse eulersPhi)
        privateKeyExponent = smallRelativePrime.modInverse(eulersPhi);
    }
}
