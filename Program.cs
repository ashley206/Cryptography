using System;
using System.Collections.Generic;
using System.Security.Cryptography;

/************************************************
*Lab 1: Ciphers
*Date:      1/15/2017
*Author:    Ashley Wagner
*
* Two ciphers are presented below: One Time Pad and Playfair. 
* Both ciphers require a string of text to encipher and 
* decipher again. 
*
* The results are displayed in NUMERIC format. One Time
* Pad will display results exactly. Playfair may not.
* 
* Playfair may have variations in the output it returns
* to the user. This is due to the inclusion of 'X' 
* characters placed in certain conditions (when the digraph
* contains the same letters, or when the string is of 
* odd length). These additional 'X's would be sifted through
* by the end user in the plaintext format and easily 
* discarded. 
*
* In Playfair, the letters I and J are also considered 
* equivalent. Thus, as well, any 'J's are replaced with I's. 
* This is another result that would be handle when a user
* was given the plaintext representation.
*
* A note on Playfair display: In order to prove the cipher 
* functions, the input text goes through a 'PrepMessage' 
* function. This would normally go inside the 'Process' 
* function and be privatized in the Playfair class. This 
* would better apply appropriate code protections where 
* necessary.
*
* Example Output: 
* ---* One Time Pad Cipher *---
* Please enter a string to encrypt: testing ciphers
* Initial input:  116 101 115 116 105 110 103 32 99 105 112 104 101 114 115
* Key:            48 78 128 113 168 81 206 209 37 20 122 190 27 69 25
* Encrypted:      164 179 243 229 273 191 309 241 136 125 234 294 128 183 140
* Decrypted:      116 101 115 116 105 110 103 32 99 105 112 104 101 114 115
* Plaintext:      testing ciphers

* ---* Playfair Cipher *---
* Please enter a key word or phrase:
* example word
* Please enter a string to encrypt:
* foxes and dogs
* Initial input: FOXESANDXDOGSX  
* 70 79 88 69 83 65 78 68 88 68 79 71 83 88
* Key:            example word
* 101 120 97 109 112 108 101 32 119 111 114 100
* Encrypted:      NFAXNPSOPWRFKP
* 78 70 65 88 78 80 83 79 80 87 82 70 75 80
* Decrypted:      FOXESANDXDOGSX
* 70 79 88 69 83 65 78 68 88 68 79 71 83 88

************************************************/

namespace L1_Ciphers
{
    class Program
    {
        static void Main(string[] args)
        {
            // One Time Pad Cipher
            Console.WriteLine("---* One Time Pad Cipher *---");
            Console.Write("Please enter a string to encrypt: ");
            string input = Console.ReadLine();
            byte[] key = OneTimePad.KeyGenerate(input);
            Console.Write("Initial input:\t");
            DisplayToInt(input);
            Console.Write("Key:\t\t");
            Display(key);
            char[] encrypt = OneTimePad.Encipher(input, key);
            char[] decrypt = OneTimePad.Decipher(encrypt, key);
            Console.Write("Encrypted:\t");
            DisplayToInt(encrypt);
            Console.Write("Decrypted:\t");
            DisplayToInt(decrypt);
            Console.Write("Plaintext:\t");
            Display(decrypt);
            Console.WriteLine();

            // Playfair Cipher
            Console.WriteLine("---* Playfair Cipher *---");
            Console.WriteLine("Please enter a key word or phrase: ");
            string key2 = Console.ReadLine();
            Console.WriteLine("Please enter a string to encrypt: ");
            string input2 = Console.ReadLine();

            // Modify the string to be without spaces and fixed for similar pairs and even length
            input2 = Playfair.PrepMessage(input2);
            Console.WriteLine("Initial input:\t" + input2);
            DisplayToInt(input2);
            Console.WriteLine("Key:\t\t" + key2);
            DisplayToInt(key2);

            string encrypt2 = Playfair.Encipher(key2, input2);
            string decrypt2 = Playfair.Decipher(key2, encrypt2);
            Console.WriteLine("Encrypted:\t" + encrypt2);
            DisplayToInt(encrypt2);
            Console.WriteLine("Decrypted:\t" + decrypt2);
            DisplayToInt(decrypt2);
            Console.ReadLine();
        }

        /****************************************
        *   Display Methods 
        ****************************************/
        static void Display(char[] input)
        {
            foreach(char c in input)
            {
                Console.Write(c);
            }
            Console.WriteLine();
        }
        static void Display(byte[] input)
        {
            for(int i = 0; i < input.Length; i++)
            {
                Console.Write(input[i] + " ");
            }
            Console.WriteLine();
        }
        static void DisplayToInt(string input)
        {
            foreach(char c in input)
            {
                Console.Write((int)c + " ");
            }
            Console.WriteLine();
        }
        static void DisplayToInt(char[] input)
        {
            foreach (char c in input)
            {
                Console.Write((int)c + " ");
            }
            Console.WriteLine();
        }
        static void DisplayToInt(int[] input)
        {
            for(int i = 0; i < input.Length; i++)
            {
                Console.Write(input[i] + " ");
            }
            Console.WriteLine();
        }
    }

    public class OneTimePad
    {
        // One key is shared between encrypter and decrypter
        public static byte [] KeyGenerate(string input)
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            int length = input.Length;
            byte[] key = new byte[length];
            rng.GetBytes(key);
            return key;
        }

        public static char[] Encipher(string input, byte[] key)
        {
            // To encrypt, add the value 
            char[] encrypt = new char[input.Length];
            for (int i = 0; i < key.Length; i++)
            {
                encrypt[i] = (char)(input[i] + key[i]);
            }
            return encrypt;
        }

        public static char[] Decipher(char[] input, byte[] key)
        {
            // To decrypt, subtract the value
            char[] decrypt = new char[input.Length];
            for(int i = 0; i < key.Length; i++)
            {
                decrypt[i] = (char)(input[i] - key[i]);
            }
            return decrypt;
        }
    }

    public class Playfair
    {
        // Differentiates between encryption and decryption to determine specific operations.
        enum Mode { Encrypt, Decrypt };

        public static string Encipher(string key, string input)
        {
            return Process(key, input, Mode.Encrypt);
        }
        public static string Decipher(string key, string input)
        {
            return Process(key, input, Mode.Decrypt);
        }

        private static string Process(string key, string input, Mode mode)
        {
            string output = String.Empty;
            int adjust = (mode == Mode.Encrypt ? 1 : -1);

            // Create the square given the key
            char[,] square = GenerateSquare(key);
            int row1 = 0, col1 = 0, row2 = 0, col2 = 0;

            // Process the input 
            for(int i = 0; i < input.Length; i += 2)
            {
                // Get the positions of two letters in the input 
                GetPosition(square, input[i], ref row1, ref col1);
                GetPosition(square, input[i + 1], ref row2, ref col2);

                // Determine where they are in the table
                if(row1 == row2)
                {
                    output += SameRow(square, row1, col1, col2, adjust);
                }
                else if(col1 == col2)
                {
                    output += SameColumn(square, col1, row1, row2, adjust);
                }
                else
                {
                    output += DifferentRowColumn(square, row1, row2, col1, col2);
                }
                // Repeat for all pairs
            }
            return output;
        }

        private static string SameColumn(char[,] square, int col, int row1, int row2, int adjust)
        {
            string retval = String.Empty;
            retval += square[(Mod((row1 + adjust), 5)), col];
            retval += square[(Mod((row2 + adjust), 5)), col];
            return retval;
        }

        private static string SameRow(char[,] square, int row, int col1, int col2, int adjust)
        {
            string retval = String.Empty;
            retval += square[row, (Mod((col1 + adjust), 5))];
            retval += square[row, (Mod((col2 + adjust), 5))];
            return retval;
        }

        private static string DifferentRowColumn(char[,] square, int row1, int row2, int col1, int col2)
        {
            string retval = String.Empty;
            retval += square[row1, col2];
            retval += square[row2, col1];
            return retval;
        }

        private static void GetPosition(char[,] square, char ch, ref int row, ref int col)
        {
            bool found = false;
            for(int i = 0; i < 5; i++)
            {
                for(int j = 0; j < 5 && found == false; j++)
                {
                    if(square[i,j] == ch)
                    {
                        row = i;
                        col = j;
                        found = true;
                    }
                }
            }
        }

        private static char [,] GenerateSquare(string key)
        {
            char[,] square = new char[5, 5];
            // Ensure J doesn't exist in the key
            key = key.ToUpper();
            key = key.Replace(" ", "");
            string newKey = key.Replace("J", "");
            newKey += "ABCDEFGHIKLMNOPQRSTUVWXYZ";
            for(int i = 0; i < newKey.Length; i++)
            {
                // Find all Occurances of that letter -- indexes in the string
                List<int> indexes = FindOccurences(newKey[i], newKey);
                // Remove all duplicates except the first
                newKey = RemoveDuplicates(newKey, indexes);
            }
            for(int i = 0; i < 25; i++)
            {
                // i/5 for row, i%5 for column
                square[(i / 5), i % 5] = newKey[i];
            }
            return square;    
        }

        private static List<int> FindOccurences(char ch, string key)
        {
            List<int> indexes = new List<int>();
            int first = key.IndexOf(ch);
            for (int i = first + 1; i < key.Length; i++)
            {
                // If characters match, at that index
                if(key[i] == ch)
                {
                    indexes.Add(i);
                }
            }
            return indexes;
        }

        private static string RemoveDuplicates(string input, List<int> indexes)
        {
            for(int i = indexes.Count - 1; i >= 0; i--)
            {
                // Remove the single character at that index
                input = input.Remove(indexes[i], 1);
            }
            return input;
        }

        public static string PrepMessage(string input)
        {
            string result = String.Empty;
            input = input.ToUpper();
            input = input.Replace(" ", "");
            // I and J are essentially equal in ciphering.
            input = input.Replace("J", "I");

            for(int i = 0; i < input.Length; i++)
            {
                result += input[i];
                // If you're not at the end of the string 
                if(i < input.Length - 1)
                {
                    // If next letter is the same as the the current
                    if(input[i] == input[i + 1])
                    {
                        // Append an 'X'
                        result += 'X';
                    }
                }
            }
            // Ensure the string is of even length
            if (result.Length % 2 != 0)
            {
                result += 'X';
            }
            return result;
        }

        // Modified modulous function to account for negative operands.
        static int Mod(int a, int b)
        {
            return (a % b + b) % b;
        }
    }
}
