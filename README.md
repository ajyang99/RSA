# RSA
An Implementation of the RSA Cryptosystem

This is an implementation of RSA Cryptosystem programmed in Racket (Scheme). I learned about RSA in MATH 145 and found it pretty 
interesting, so I decided to implement it in Racket, which was the language I was learning in CS 145. 

Here is a good read about why RSA works mathematically: http://www.mathaware.org/mam/06/Kaliski.pdf

And here is how to en/decrypt a message using the RSA algorithm written by me:

The main program contains 3 parts: A generatesthe public key (n, e) and sends it to B, B encrypts the letter message into cyphertext
(a number c) and sends c back to A, and A decipher the message using c, n and private key d. 

To be more specific, 

(1) The function "generate" takes in a number l (so that the n generated will have at least (2*l-1) digits), and produces public key 
(n, e), a pair of primes (p, q) (which don't need to be shown but I just put them down here for your information), and private key d. 
A should distribute (n, e) to B and write down (p, q) and d somewhere safe to make sure no one else can see them. 

(2) Upon receiving the public key (n, e), B will use the function "encrypt" to encrypt his letter message into number c and send it to
A. It is worth noting that all the letters in the message should be in capital letters, the message is first coded into a number (which
should be smaller than n) by its ASCII code (eg: "ABC" -> 656667), so the length of the message will not exceed n / 2 (since each letter
takes up 2 digits).

(3) Upon receiving the cyphertext c, A will use the function "decrypt" to decrypt/recover the letter message with the knowledge of c, n 
and d.
