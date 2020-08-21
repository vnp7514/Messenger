/**
 * File: Program.cs
 * Author: Van Pham  vnp7514@rit.edu
 * Description: A Program that encrypts or decrypts messages with RSA.
 */
using System;
using System.Threading.Tasks;

namespace Messenger
{
    class Program
    {
        /**
         * Main method of the program
         * There are 5 options for it to take.
         * If the given arguments do not match any of the options, an
         *   error message is printed and the program exits.
         * Param:
         *      args   the list of arguments
         */
        static void Main(string[] args)
        {
            Messenger ms = new Messenger();
            if (args.Length == 2)
            {
                if (args[0] == "keyGen")
                {
                    try
                    {
                        Int64 keysize = Int64.Parse(args[1]);
                        ms.KeyGen(keysize);
                    } 
                    catch (OverflowException)
                    {
                        Console.WriteLine(args[1] + " is out of range of Int64 type.");
                        PrintHelp();
                    } 
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message);
                        PrintHelp();
                    }

                }
                else if (args[0] == "sendKey")
                {
                   Task.WaitAll(ms.SendKey(args[1]));
                }
                else if (args[0] == "getKey")
                {
                   Task.WaitAll(ms.GetKey(args[1]));
                }
                else if (args[0] == "getMsg")
                {
                    Task.WaitAll(ms.GetMsg(args[1]));
                }
                else
                {
                    Console.WriteLine("Invalid arguments.");
                    PrintHelp();
                }
            }
            else if (args.Length == 3 && args[0] == "sendMsg")
            {
                Task.WaitAll(ms.SendMsg(args[1], args[2]));
            }
            else
            {
                Console.WriteLine("Invalid arguments.");
                PrintHelp();
                
            }
        }
        
        /** 
         * Print the help screen and tell the program to stop with an error code 1
         */
        private static void PrintHelp()
        {
            Console.WriteLine("dotnet run <option> <other arguments>");
            Console.WriteLine("Options:");
            Console.WriteLine("\tkeyGen  <keysize>");
            Console.WriteLine("\tsendKey <email>");
            Console.WriteLine("\tgetKey  <email>");
            Console.WriteLine("\tsendMsg <email> <plaintext>");
            Console.WriteLine("\tgetMsg  <email>");
            System.Environment.Exit(1);
        }
    }
}
