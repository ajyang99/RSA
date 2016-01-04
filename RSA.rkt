#lang racket
;; An implementation of the RSA (Rivest-Shamir-Adleman) crytosystem which is one of the first practical public-key cryptosystems
;; and is widely used for secure data transmission (Wikipedia, RSA (cryptosystem)
;; Written by Joyce Yang, 12/27/2015

;; How it works:
;; The RSA algorithm involves four steps: key generation, key distribution, encryption and decryption

;; The function generate will generate two primes p and q, their product n (= p*q) which will be part of the public key,
;; e, which is the other part of the public key (gcd(e,phi(n))=1), and d which is the private key only revealed to the person
;; (say, Alice) who generates and sends the public key

;; The distribution step means that Alice sends the public key to Bob, but it is trivial to program here

;; The function encrypt will encrypt a string (of letters) m into cyphertext c by the public key given and Bob will send c
;; back to Alice

;; The function decrypt will help Alice decode the message using only the cyphertext c, the private key d she would know from
;; earlier, and n

;; An Example:
;; Say (generate 2) gives (list (tuple 143 17) (11 13) 113) (because both 11 and 13 are 2-digit primes, 143 = 11 * 13,
;; gcd (17, 120) = 1 (phi(143)=10*12=120), and 17*113 = 1 mod 120 (so public key is (143 17) and private key is 113)

;; So Alice sends (tuple 143 17) to Bob

;; Say Bob has the message "U", then (encrypt (tuple 143 17) "U") will give Bob c = 24
;; Warning: the message is all in capital letters
;; and the length of the message is limited by the number of digits of n, to be more exact,
;; number of letters in the message = (number of digits of n) div 2 (because each letter is coded to a 2-digit number)

;; And Bob sends c = 24 back to Alice

;; (decrypt 24 113 143) (24 is the cyphertext, 113 is the private key, and 143 is n) will give Alice "U"

(struct tuple (fst snd) #:transparent)

;*****************************************************************************************************************************;
;****** A first generates public key (n, e) and primes (p,q) and private key d that only A knows *****************************;
;*****************************************************************************************************************************;

;; generate: number -> (list (tuple number number) (tuple number number) number)
;; consumes a number l, which represents the number of the digits there will be in prime numbers p and q
;; (to make things easier we will just let p and q to have the same number of digits)
;; and produces a list containing a tuple (n, e) representing the public key, a tuple (p, q)
;; representing the two primes chosen and a number d which is the private key (d*e=1 mod phi(n))
(define (generate l)
  (let* ([lst (generate-prime-list l)]
         [lst2 (filter (lambda (x) (>= x (expt 10 (sub1 l)))) lst)]
         [p (list-ref lst2 (random (length lst2)))]
         [q (unique lst2 p)]
         [n (* p q)]
         [phi (* (sub1 p) (sub1 q))]
         [e (generate-e phi lst)]
         [d (generate-d e phi)])
    (list (tuple n e) (tuple p q) d)))

;; generate-prime-list: number number -> listof numbers
;; consumes a number l and n and produces a list of the primes starting from n which have l digits
;; Example: (generate-prime-list 1) will give (list 2 3 5 7)
(define (generate-prime-list l)
  (let* ([y (expt 10 l)] [lst (build-list y (lambda (x) x))])
    (sieve (remove 1 (remove 0 lst)) y)))

;; sieve: (listof numbers) number -> (listof numbers)
;; use sieve of eratosthenes to generate a list of primes which have at most l digits
;; i.e. sieve out multiples of the first element of the list (excluding the first element itself)
;; and move on to the next element
(define (sieve lst y)
  (cond [(empty? lst) empty]
        [(> (first lst) (sqrt y)) lst]
        [else (let ([x (first lst)])
                (cons x (sieve (filter (lambda (p) (not (zero? (remainder p x)))) (rest lst)) y)))]))

;; generate a different number (q) in the list other than p
(define (unique lst p)
  (let ([q (list-ref lst (random (length lst)))])
    (if (equal? p q) (unique lst p) q)))

;; generate e such that e < phi and gcd(e, phi)=1
(define (generate-e phi lst)
  (let ([e (list-ref lst (random (length lst)))])
    (if (or (>= e phi) (zero? (remainder phi e))) (generate-e phi lst) e)))

;; generate d such that d*e = 1 mod phi
(define (generate-d e phi)
  (match (back-subst phi e)
    ; s*phi + e*t = 1, so d = t mod phi is what we are looking for
    [(tuple s t) (modulo-adjust t phi)]))

;; euclidean-algorithm: number number -> (listof (tuple number number))
;; simulation of the Euclidean Algorithm
;; consumes two integers x, y with x >= y and produces a list of tuples containing integers
;; q(n)'s and r(n)'s with q1 = x div y, r1 = x mod y, q2 = y div r1, r2 = y mod r2, ...
;; q(n) = r(n-2) div r(n-1), r(n) = r(n-2) mod r(n-1), where r(n) is the last remainder which
;; is not zero, and which also happens to be gcd(x, y)
(define (euclidean-algorithm x y)
  (cond [(zero? (remainder x y)) empty]
        [else (let ([q (quotient x y)] [r (remainder x y)])
                (cons (tuple q r) (euclidean-algorithm y r)))]))

;; back-subst: number number -> (tuple number number)
;; simulation of the Back-Substitution Algorithm
;; consumes two integers x, y with x >= y and produces a tuple containing integers s and t
;; such that x*s + y*t = d, where d = gcd(x, y)
(define (back-subst x y)
  (if (zero? (remainder x y))
      (tuple 0 (sub1 (quotient y x)))
      (let* ([ea-lst (map (lambda (x) (tuple-fst x)) (reverse (euclidean-algorithm x y)))]
             ;ea-lst is the list of reversed q(n)'s from EA i.e. ea-lst = (list q(n) q(n-1) ... q(1))
             [bs-lst (back-substh (rest ea-lst) (list (- 0 (first ea-lst)) 1))])
             ;the bs sequence goes like this: s(0)=1, s(1)=-q(n), s(2)=(-q(n-1))*s(1)+s(0),
             ;..., s(m)=(-q(n+1-m))*s(m-1)+s(m-2), and s=s(n-1), t=s(n)
             (tuple (second bs-lst) (first bs-lst)))))

;; back-substh: (listof numbers) (listof numbers) -> (listof numbers)
;; helper function of back-subst that consumes a list of (tuple q r) and produces
;; (list s(n) s(n-1) s(n-2) ... s(1) s(0))
(define (back-substh ea-lst bs-lst)
  (cond [(empty? ea-lst) bs-lst]
        [else (back-substh (rest ea-lst) (cons (+ (* (- 0 (first ea-lst)) (first bs-lst)) (second bs-lst))
                                               bs-lst))]))

;; modulo-adjust number number -> number
;; consumes two integers x, n and produces y, where y = x mod n with 0 <= y < n
(define (modulo-adjust x n)
  (cond [(and (<= 0 x) (< x n)) x]
        [(< x 0) (+ n (remainder x n))]
        [else (remainder x n)]))

;*****************************************************************************************************************************;
;****** B then encrpts his letter message msg, converts it to c by the public key and sends it to A **************************;
;*****************************************************************************************************************************;

;; encrypt: tuple number -> number
;; converts the converted message m into c (c = m^e mod n) by the square-and-multiply method
(define (encrypt public-key msg)
  (let ([m (str->integer msg)]) ; first converts msg into an integer by its ASCII code
    (match public-key
      [(tuple n e) (let* ([x (log-2 e)] [lst (square x m n)]) (multiply lst e n))])))

;; str->integer: string -> number
;; converts a message into integers according to its ASCII code
;; Examples: "ABC" -> 656667
(define (str->integer s)
  (let ([slst (string->list s)])
    (foldl (lambda (char result) (let ([n (char->integer char)]) (+ (* result 100) n)))
           0
           slst)))

;; log-2: number -> number
;; calculates (floor (log2 e))
(define (log-2 e)
  (cond [(< e 2) 0] [else (add1 (log-2 (quotient e 2)))]))

;; square: number number number -> (listof numbers)
;; consumes integers x m and n and produces a list containing (x+1) elements where the (x+1-i)th element
;; represents m^(2^i) mod n
(define (square x m n)
  (cond [(zero? x) (list (remainder m n))]
        [else (let ([lst (square (sub1 x) m n)]) (cons (remainder (expt (first lst) 2) n) lst))]))

;; multiply: (listof number) number number -> number
;; consumes a list resulted from the function square, the exponent e and n to calculate m^e mod n
;; by the square and multiply method (i.e. 10^47 = 10^32 + 10^8 + 10^4 + 10^2 + 10^1 mod 3)
(define (multiply lst e n)
  (cond [(zero? e) 1]
        [else (let ([y (expt 2 (sub1 (length lst)))])
           (if (>= e y)
               (remainder (* (first lst) (multiply (rest lst) (- e y) n)) n)
               (multiply (rest lst) e n)))]))

;*****************************************************************************************************************************;
;*******Finally A decrpts the message by c, d and n **************************************************************************;
;*****************************************************************************************************************************;

;; decrypt: number number number -> string
;; consumes the cyphertext c, private code d and integer n and produces the decrypted message
;; by m = (c^d) mod n
;; WHY IT WORKS (mathematicallly)
;; Since n is the product of two distinct primes, m^(phi(n)+1) = m mod n (proof uses Fermat's Little Theorem)
;; Since e*d = 1 mod phi(n), c^d = (m^e)^d = m^(e*d) = m^(k*phi(n) + 1) = m mod n
(define (decrypt c d n)
  (let* ([x (log-2 d)]
         [lst (square x c n)]
         [y (multiply lst d n)])
    (integer->str y)))

;; integer->str: number -> string
;; converts an integer into a string (message) according to its ASCII code
;; Examples: 656667 -> "ABC"
(define (integer->str m)
  (local [(define (integer->list n)
            (cond [(< n 100) (list (integer->char n))]
                  [else (cons (integer->char (remainder n 100)) (integer->list (quotient n 100)))]))]
   (list->string (reverse (integer->list m)))))