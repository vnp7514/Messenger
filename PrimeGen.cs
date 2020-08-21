/**
 * File: PrimeGen.cs
 * Author: Van Pham  vnp7514@rit.edu
 * Description: This class generates a prime number with the provided bits size
 * This class utilizes the Parallel Library.
 * The constructor takes in a number representing the bit size
 * Use the method generate to generate a prime number. It will return a BigInteger instance.
 */

using System;
using System.Numerics;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace Messenger
{
    public class PrimeGen
    {
        // The maximum size of the prime number to generate
        Int64 bits;
        // The random number generator
        private RNGCryptoServiceProvider rngCrypt = new RNGCryptoServiceProvider();

        /**
         * A constructor for the PrimeGen class
         * 
         * param: 
         *       bits   the size of the prime numbers to generate
         * 
         * pre-condition:
         *       bits is non-negative and a multiple of 8
         */
        public PrimeGen(Int64 bits)
        {
            this.bits = bits;
        }

        /**
         * generate a prime number.
         * Return:
         *      A prime number of the specified size
         */
        public BigInteger generate()
        {
            BigInteger prime = new BigInteger(-1);
            Int64 size = bits / 8;
            var pa = Parallel.For(0, Int64.MaxValue, (i, state) =>
            {
                try
                {
                    var randomNumber = new byte[size];
                    rngCrypt.GetBytes(randomNumber);//Fill the randomNumber with values
                    var newPrime = new BigInteger(randomNumber);
                    if (newPrime.IsProbablyPrime())
                    {
                        state.Stop();
                        prime = newPrime;
                    }
                }
                catch
                {
                    Console.WriteLine("Encounter an error when " +
                        "trying to generate a prime number");
                }
            });
            if (prime == -1)
            {// still haven't found the prime number after a lot of iterations
                return this.generate(); // run this again
            }
            return prime;
        }

        /**
         * End the PrimeGenerator program. Do cleanup
        */
        public void terminate()
        {
            try
            {
                rngCrypt.Dispose();
            }
            catch
            {
                Console.WriteLine("Unable to dispose RNGCryptoServiceProvider");
            }
        }
    }

    public static class Extensions
    {
        public static Boolean IsProbablyPrime(this BigInteger value, int witnesses = 10)
        {
            if (value <= 1) return false;
            if (witnesses <= 0) witnesses = 10;
            BigInteger d = value - 1;
            int s = 0;
            while (d % 2 == 0)
            {
                d /= 2; s += 1;
            }
            Byte[] bytes = new Byte[value.ToByteArray().LongLength];
            BigInteger a;
            for (int i = 0; i < witnesses; i++)
            {
                do
                {
                    var Gen = new Random();
                    Gen.NextBytes(bytes);
                    a = new BigInteger(bytes);
                } while (a < 2 || a >= value - 2);

                BigInteger x = BigInteger.ModPow(a, d, value);
                if (x == 1 || x == value - 1) continue;
                for (int r = 1; r < s; r++)
                {
                    x = BigInteger.ModPow(x, 2, value);
                    if (x == 1) return false;
                    if (x == value - 1) break;
                }

                if (x != value - 1) return false;
            }
            return true;
        }
    }
}
