;;;
;;; Module: DES implementation for Racket Crypto library
;;; Author: Dmitry A. Paramonov (c) 2013
;;; License: BSD
;;;
;;; TODO:
;;; 1. DES3 enc/dec
;;; 2. Ability to encrypt more than 64 bits of data
;;; 3. Crypt modes (ecb, cbc, etc...)
;;; 4.(!) Auto complement input string if its length is not a multile of 64 (bits)
;;; 5(!). Functions to check key weakness
;;; 6. Add contracts and make interface functions to encrypt either
;;; an integer of a byte string
;;; 7. Try to memoize some functions (e.g. key-schedule)
#lang racket

(require rackunit "utils.rkt")

(provide des-encrypt des-decrypt)

;; S-tables from 1 to 8 to process through S-blocks
(define S1-table '(14 4 13 1 2 15 11 8 3 10 6 12 5 9 0 7
                   0 15 7 4 14 2 13 1 10 6 12 11 9 5 3 8
                   4 1 14 8 13 6 2 11 15 12 9 7 3 10 5 0
                   15 12 8 2 4 9 1 7 5 11 3 14 10 0 6 13))
(define S2-table '(15 1 8 14 6 11 3 4 9 7 2 13 12 0 5 10
                   3 13 4 7 15 2 8 14 12 0 1 10 6 9 11 5
                   0 14 7 11 10 4 13 1 5 8 12 6 9 3 2 15
                   13 8 10 1 3 15 4 2 11 6 7 12 0 5 14 9))
(define S3-table '(10 0 9 14 6 3 15 5 1 13 12 7 11 4 2 8
                   13 7 0 9 3 4 6 10 2 8 5 14 12 11 15 1
                   13 6 4 9 8 15 3 0 11 1 2 12 5 10 14 7
                   1 10 13 0 6 9 8 7 4 15 14 3 11 5 2 12))
(define S4-table '(7 13 14 3 0 6 9 10 1 2 8 5 11 12 4 15
                   13 8 11 5 6 15 0 3 4 7 2 12 1 10 14 9
                   10 6 9 0 12 11 7 13 15 1 3 14 5 2 8 4
                   3 15 0 6 10 1 13 8 9 4 5 11 12 7 2 14))
(define S5-table '(2 12 4 1 7 10 11 6 8 5 3 15 13 0 14 9
                   14 11 2 12 4 7 13 1 5 0 15 10 3 9 8 6
                   4 2 1 11 10 13 7 8 15 9 12 5 6 3 0 14
                   11 8 12 7 1 14 2 13 6 15 0 9 10 4 5 3))
(define S6-table '(12 1 10 15 9 2 6 8 0 13 3 4 14 7 5 11
                   10 15 4 2 7 12 9 5 6 1 13 14 0 11 3 8
                   9 14 15 5 2 8 12 3 7 0 4 10 1 13 11 6
                   4 3 2 12 9 5 15 10 11 14 1 7 6 0 8 13))
(define S7-table '(4 11 2 14 15 0 8 13 3 12 9 7 5 10 6 1
                   13 0 11 7 4 9 1 10 14 3 5 12 2 15 8 6
                   1 4 11 13 12 3 7 14 10 15 6 8 0 5 9 2
                   6 11 13 8 1 4 10 7 9 5 0 15 14 2 3 12))
(define S8-table '(13 2 8 4 6 15 11 1 10 9 3 14 5 0 12 7
                   1 15 13 8 10 3 7 4 12 5 6 11 0 14 9 2
                   7 11 4 1 9 12 14 2 0 6 10 13 15 3 5 8
                   2 1 14 7 4 10 8 13 15 12 9 0 3 5 6 11))

;; all S tables with additional info
;; the two-element list of additional info is a row number
;; formed from 6 input bits (each element is a bit number)
;; the four-element list is a column nuber 
;; formed from 6 input bits (each element is a bit number)
(define S-tables `(((47 42) (46 45 44 43) ,S1-table)
                   ((41 36) (40 39 38 37) ,S2-table)
                   ((35 30) (34 33 32 31) ,S3-table)
                   ((29 24) (28 27 26 25) ,S4-table)
                   ((23 18) (22 21 20 19) ,S5-table)
                   ((17 12) (16 15 14 13) ,S6-table)
                   ((11 6) (10 9 8 7) ,S7-table)
                   ((5 0) (4 3 2 1) ,S8-table)))

;; Initial Permutation table
(define IP-table '(58 50 42 34 26 18 10 2
                   60 52 44 36 28 20 12 4
                   62 54 46 38 30 22 14 6
                   64 56 48 40 32 24 16 8
                   57 49 41 33 25 17 9 1
                   59 51 43 35 27 19 11 3
                   61 53 45 37 29 21 13 5
                   63 55 47 39 31 23 15 7))

(define IP-1-table '(40 8 48 16 56 24 64 32
                     39 7 47 15 55 23 63 31
                     38 6 46 14 54 22 62 30
                     37 5 45 13 53 21 61 29
                     36 4 44 12 52 20 60 28
                     35 3 43 11 51 19 59 27
                     34 2 42 10 50 18 58 26
                     33 1 41 9 49 17 57 25))

;; Permutation with Extension table
(define EP-table '(32 1 2 3 4 5
                   4 5 6 7 8 9
                   8 9 10 11 12 13
                   12 13 14 15 16 17
                   16 17 18 19 20 21
                   20 21 22 23 24 25
                   24 25 26 27 28 29
                   28 29 30 31 32 1))

;; P-table
(define P-table '(16 7 20 21
                  29 12 28 17
                  1 15 23 26
                  5 18 31 10
                  2 8 24 14
                  32 27 3 9
                  19 13 30 6
                  22 11 4 25))

;;PC1-table
(define PC1-table '(57 49 41 33 25 17 9
                    1 58 50 42 34 26 18
                    10 2 59 51 43 35 27
                    19 11 3 60 52 44 36
                    63 55 47 39 31 23 15
                    7 62 54 46 38 30 22
                    14 6 61 53 45 37 29
                    21 13 5 28 20 12 4))

;; PC2-table
(define PC2-table '(14 17 11 24 1 5
                    3 28 15 6 21 10
                    23 19 12 4 26 8
                    16 7 27 20 13 2
                    41 52 31 37 47 55
                    30 40 51 45 33 48
                    44 49 39 56 34 53
                    46 42 50 36 29 32))

;; circular rotations for the key
(define V '(1 1 2 2 2 2 2 2 1 2 2 2 2 2 2 1))

;; rotates integer left by n bits
(define (rotate-left int int-len n-bits)
  (let ((n-mod-len (remainder n-bits int-len)))
    (bitwise-and
      (bitwise-ior (arithmetic-shift int n-mod-len)
                   (bitwise-bit-field int (- int-len n-mod-len) int-len))
      (bit-list->integer (for/list ((i (range int-len))) 1)))))

;; processing through S blocks
(define (S chunk)
  ;; get dimension (row/col) value
  (define (get-dim x n)
    (bit-list->integer
      (for/list ((i n))
        (list-ref (reverse x) i))))
  (permutation chunk 48 S-tables
               #:perm-func
               (lambda (l x)
                 (let ((row (get-dim l (car x)))
                       (col (get-dim l (cadr x))))
                   (integer->bit-list
                     (list-ref (caddr x) (+ (* 16 row) col))
                     4)))))

;; PC-1 permutation (for the key)
(define (PC1 chunk)
  (permutation chunk 64 PC1-table))

;;PC-2 permutation
(define (PC2 chunk)
  (permutation chunk 56 PC2-table))

;; permutation in P-block
(define (P chunk)
  (permutation chunk 32 P-table))

;; permutation with extension
;; input 32 bit, output 48 bit
(define (E chunk)
  (permutation chunk 32 EP-table))

;;do initial permutation according with IP-table
(module+ test
  (check-equal? (IP 0) #x0 "simple initial permutation test")
  (check-equal? (IP #xffffffffffffffff)
                #xffffffffffffffff
                "simple initial permutation test")
  (check-equal? (IP #xfffeffffffffffff)
                #xfffffffdffffffff
                "simple initial permutation test"))

(define (IP chunk)
  (permutation chunk 64 IP-table))

(define (IP-1 chunk)
  (permutation chunk 64 IP-1-table))

;; Generates N round 48-bit keys from given 56-bit key
(define (key-schedule key n)
  ;; helper. rotates left every half of an integer (i) of length len
  ;; by n bits
  (define (rotate-halves i len n)
    (let* ((half-len (quotient len 2))
           (l (bitwise-bit-field i half-len len))
           (r (bitwise-bit-field i 0 half-len)))
      (bitwise-ior
        (arithmetic-shift
          (rotate-left l half-len n)
          half-len)
        (rotate-left r half-len n))))
  ;; helper. generates a schedule for 56-bit key (k)
  ;; using for n rounds
  ;; r - current round
  ;; acc - resulting list accumulator
  (define (key-56-sched k n r acc)
    (if (>= r n)
        (reverse acc)
        (let ((new-key (rotate-halves k 56 (list-ref V r))))
          (key-56-sched
            new-key
            n
            (add1 r)
            (cons (PC2 new-key) acc)))))
  (key-56-sched (PC1 key) n 0 '()))

;; round function
(define (round-func r key)
  (P (S (bitwise-xor (E r) key))))

;; main Feistel's net procedure
;; round-func - functions which represents round transformations;
;; accepts two args, the first is a left half of a chunk,
;; the second is a round key
;; n - length of a chunk
;; blk - a block being encrypted
;; keys - list of keys generated by schedule function
;; output: encrypted/decrypted chunk
(define (process-block blk keys n round-func)
  (if (null? keys)
      blk
      (process-block (swap-lr
                       blk n
                       #:mutate (lambda (l r)
                                  (list
                                    (bitwise-xor l (round-func r (car keys)))
                                    r)))
                     (cdr keys) n round-func)))

;; main auxiliary encrypt and decrypt functions
(module+ test
  (check-equal? (des-encrypt #x4E6F772069732074 #x0123456789ABCDEF)
                #x3FA40E8A984D4815 "des-encrypt")
  (check-equal? (des-decrypt #x3FA40E8A984D4815 #x0123456789ABCDEF)
                #x4E6F772069732074  "des-decrypt"))

(define (des-encrypt blk key)
  (IP-1 (swap-lr
              (process-block (IP blk) (key-schedule key 16)
                             64 round-func)
              64)))

(define (des-decrypt crypted-blk key)
  (IP-1 (swap-lr
              (process-block (IP crypted-blk)
                             (reverse (key-schedule key 16))
                             64 round-func)
              64)))

;; DES encrypt function
;; msg - bytes
;; key - 64-bit integer
;(define (des-encrypt msg key #:mode (mode 'ecb) #:iv (iv 0))
;  (define (aux-enc msg key acc)
;    (if (zero? (bytes-length msg))
;        acc
;        (case mode
;          ('ecb
;           ())
;          ('cbc
;           ())
;          ('ofb
;           ())
;          ('cfb
;           ()))))
;  (aux-enc (if (not (zero? (remainder (bytes-length msg) 8)))
;               (complement msg 64)
;               msg)
;           key
;           (make-bytes)))

;; DES decrypt function
;; msg - bytes
;; key - 64-bit integer
;(define (des-decrypt msg key #:mode (mode 'ecb) #:iv (iv 0))
;  ())

;; predicate which determines whether the DES key is weak or not
(module+ test
  (check-equal? (des-weak-key? #x0101010101010101) #t "weak key?")
  (check-equal? (des-weak-key? #xE0E0E0E0F1F1F1F1) #t "weak key?"))

(define (des-weak-key? key)
  (let ((plain-text #x0123456789ABCDEF))
    (= (des-encrypt
         (des-encrypt plain-text key)
         key)
       plain-text)))

;; predicate which determines whether a pair of DES keys is a semi-weak
(module+ test  (check-equal? (des-semi-weak-keys? #x01E001E001F101F1 #xE001E001F101F101)
                #t "semi-weak keys?"))

(define (des-semi-weak-keys? k1 k2)
  (let ((plain-text #x0123456789ABCDEF))
    (= (des-encrypt
         (des-encrypt plain-text k1)
         k2)
       plain-text)))

