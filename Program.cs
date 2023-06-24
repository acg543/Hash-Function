using System;
using System.Security.Cryptography;
using System.Text;

/*
    Alex Grenier, 6/23/23
    The purpose of this Hash function is to intake strings and salt and create hash values.
    I used SHA512 because it is less prone to collision attacks and more rounds of operations at little cost.
    I did this in C# because I have no experience with it and want to learn some basics.
*/
public class HashFunction {
    public static string Hashy(string input, string salt) {
        // Convert the salt and input string to byte arrays
        byte[] saltBytes = Encoding.UTF8.GetBytes(salt);
        byte[] inputBytes = Encoding.UTF8.GetBytes(input);

        // Create a new instance of the Rfc2898DeriveBytes class to generate a secure key from the salt and password
        using (var deriveBytes = new Rfc2898DeriveBytes(inputBytes, saltBytes, 10000, HashAlgorithmName.SHA512)) {
            // Generate the key
            byte[] keyBytes = deriveBytes.GetBytes(64); // 64 bytes for 512-bit key

            // Create a new instance of the HMACSHA512 class with the generated key
            using (var hmac = new HMACSHA512(keyBytes)) {
                // Compute the hash of the input string
                byte[] hashBytes = hmac.ComputeHash(inputBytes);

                // Create a StringBuilder to collect the bytes and create a string
                StringBuilder stringBuilder = new StringBuilder();

                // Loop through each byte of the hashed data and format it as a hexadecimal string
                for (int i = 0; i < hashBytes.Length; i++) {
                    // Append each byte as a two-digit hexadecimal representation
                    stringBuilder.Append(hashBytes[i].ToString("x2"));
                }

                // Return the hexadecimal string
                return stringBuilder.ToString();
            }
        }
    }

    public static void Main(string[] args)
    {
        // These values are predetermined, but ideally the salt value would be a random string the same length as the hash
        string input = "J@guAR$faN01!";
        string salt = "addSomeSalt";

        // Compute the SHA512 hash of the input string with salt
        string hash_value = Hashy(input, salt);

        // Print the input string, salt, and the corresponding hash
        Console.WriteLine($"Input: {input}");
        Console.WriteLine($"Salt: {salt}");
        Console.WriteLine($"SHA512 Hash (with salt): {hash_value}");
    }
}