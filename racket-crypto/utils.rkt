;;;
;;; Module: Utility module for Racket Crypto library
;;; Author: Dmitry A. Paramonov (c) 2013
;;; License: BSD
;;;
#lang racket

;(require data/bit-vector)

(provide (struct-out block))

(provide permutation swap-lr
         integer->bit-list
         bit-list->integer
         complement make-block
         left-proc right-proc
         block-val block-swap)

; helpers for converting integer to bit vectors and vice versa
;(define (integer->bit-vector int int-size)
;  (for/bit-vector ((i (in-range int-size)))
;    (= (bitwise-bit-field int i (add1 i)) 1)))
;
;(define (bit-vector->integer bv)
;  (foldr (lambda (v acc)
;           ())
;         0
;         (bit-vector->list bv)))

;; swaps left and right halves of an integer of lengh n
;; additional mutator allows to change values of either left
;; and right halves; changes are applied before swapping
;; n must ne even
(define (swap-lr int n #:mutate (m (lambda (l r) (list l r))))
  (let ((l (bitwise-bit-field int (quotient n 2) n))
        (r (bitwise-bit-field int 0 (quotient n 2))))
    (bitwise-ior (arithmetic-shift (cadr (m l r)) (quotient n 2))
                 (car (m l r)))))

;; complements a byte string to the length which is a multiple of n bits
;; assume that length of bs is a multiple of 8
(define (complement bs n)
  (let ((b (- n
              (remainder (* 8 (bytes-length bs)) n))))
    (bytes-append bs (make-bytes (quotient n 8)))))

;; converts a list of bits to an integer
(define (bit-list->integer bits-lst)
  (define (iter lst acc)
    (if (null? lst)
        acc
        (iter (cdr lst)
              (bitwise-ior
                (arithmetic-shift (car lst)
                                  (sub1 (length lst)))
                acc))))
  (iter bits-lst 0))

;; converts integer of length int-len to the list of bits
(define (integer->bit-list int int-len)
  (reverse (foldr (lambda (v l)
                    (cons (bitwise-bit-field int v (add1 v)) l))
                  '()
                  (range int-len))))

;; common permutation function
;; int - integer
;; int-len - length of the integer
;; perm-tab - permutation table
;; perm-func - permutation function
;; output: sequence of permutated bits
(define (permutation int int-len perm-tab
                     #:perm-func (perm-func (lambda (l x)
                                              (list-ref l (sub1 x)))))
  ;; integer as list of bits
  (define (l-perm l perm-tab perm-func)
    (for/list ((x perm-tab))
              (perm-func l x)))
  (bit-list->integer
    (flatten (l-perm (integer->bit-list int int-len) perm-tab perm-func))))

;; TODO: implement all modes
;(define (cipher-mode #:mode (mode 'ecb) #:operation (op 'enc) #:iv (iv 0))
;  (cond ((eqv? op 'enc)
;         (cipher-enc mode))
;        ((eqv? op 'dec)
;         (cipher-dec mode))))
;
;(define ((cipher-enc c-func iv-func) enc-func msg key iv blk-size cipher-blk)
;  ())
;
;(define ecb-enc (cipher-enc
;                  (lambda (m k)
;                    ())
;                  (lambda (m k)
;                    ())))
;
;(define (cipher-dec mode)
;  ())
;
;(define (ofb enc-func msg key iv blk-size cipher-blk acc)
;  (if (zero? (bytes-length msg))
;      acc
;      (let ((start (quotient blk-size 8))
;            (O (enc-func iv key)))
;        (ofb enc-func
;             (subbytes msg start)
;             key
;             O
;             blk-size
;             cipher-blk
;             (bytes-append acc
;                           (integer->bytes
;                             (bitwise-xor
;                               (bitwise-bit-field O 0 blk-size)
;                               (bytes->integer
;                                 (subbytes msg 0 start)))
;                             cipher-blk))))))
;
;(define (ecb enc-func msg key iv blk-size cipher-blk acc)
;  (if (zero? (bytes-length msg))
;      acc
;      (let ((start (quotient blk-size 8)))
;        (ecb enc-func
;             (subbytes msg start)
;             key
;             iv
;             blk-size
;             cipher-blk
;             (bytes-append acc
;                           (integer->bytes
;                             (enc-func (bytes->integer
;                                         (subbytes msg 0 start)) key)
;                             cipher-blk))))))
;
;(define (cbc enc-func msg key iv blk-size cipher-blk acc)
;  (if (zero? (bytes-length msg))
;      acc
;      (let ((start (quotient blk-size 8))
;            (E (enc-func (bitwise-xor
;                           iv
;                           (bytes->integer
;                             (subbytes msg 0 start)))
;                         key)))
;        (cbc enc-func
;             (subbytes msg start)
;             key
;             E
;             blk-size
;             cipher-blk
;             (bytes-append acc
;                           (integer->bytes E cipher-blk))))))
;
;(define (cfb enc-func msg key iv blk-size cipher-blk acc)
;  (if (zero? (bytes-length msg))
;      acc
;      (let ((start (quotient blk-size 8)))
;        ())))

;; block abstraction

;; block structure
(struct block (left right len))

;; create block from val with length val-len bits
(define (make-block val val-len)
  (let ((half-len (quotient val-len 2)))
    (block
      (bitwise-bit-field val half-len val-len)
      (bitwise-bit-field val 0 half-len)
      val-len)))

;; apply a proc to the left half and return new block
(define (left-proc b proc)
  (block
    (proc (block-left b))
    (block-right b)
    (block-len b)))

;; -- right half
(define (right-proc b proc)
  (block
    (block-left b)
    (proc (block-right b))
    (block-len b)))

;; swap left and right halves
(define (block-swap b)
  (block
    (block-right b)
    (block-left b)
    (block-len b)))

;; returns the value of the block (joined left and right halves)
(define (block-val b)
  (bitwise-ior
    (arithmetic-shift
      (block-left b)
      (quotient (block-len b) 2))
    (block-right b)))

;;end of the block abstraction
