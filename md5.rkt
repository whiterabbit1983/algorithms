#lang racket

(require rackunit)

(provide md5)

;; four auxiliary functions, like described in RFC 1321
(define (F a b c)
  (bitwise-ior
   (bitwise-and a b)
   (bitwise-and
    (bitwise-not a) c)))

(define (G a b c)
  (bitwise-ior
   (bitwise-and a c)
   (bitwise-and b
                (bitwise-not c))))

(define (H a b c)
  (bitwise-xor a b c))

(define (I a b c)
  (bitwise-xor b
               (bitwise-ior a (bitwise-and (bitwise-not c) #xffffffff))))

;; initial values of words
(define word-A #x67452301)
(define word-B #xEFCDAB89)
(define word-C #x98BADCFE)
(define word-D #x10325476)

;; table
(define T (build-vector 64
                        (lambda (el)
                          (inexact->exact (truncate (* 4294967296
                                                       (abs (sin (add1 el)))))))))

;; X indexes
(define X '((0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15)
            (1 6 11 0 5 10 15 4 9 14 3 8 13 2 7 12)
            (5 8 11 14 1 4 7 10 13 0 3 6 9 12 15 2)
            (0 7 14 5 12 3 10 1 8 15 6 13 4 11 2 9)))

;; list of S values
(define S '((7 12 17 22)
            (5 9 14 20)
            (4 11 16 23)
            (6 10 15 21)))

;; creates an integer from a list of bytes with given bit field length
(define (bytes->integer bytes bit-length)
  (if (= (bytes-length bytes) 0)
      0
      (+ (* (bytes-ref bytes 0)
            (expt 2 (* (- (bytes-length bytes) 1) bit-length)))
         (bytes->integer (subbytes bytes 1) bit-length))))

;; converts an integer to a list of bytes with given bit field length
(module+ test
  (check-equal? (integer->bytes 6684672 24 6) (bytes 25 32 0 0) "integer->bytes")
  (check-equal? (integer->bytes 6684672 24 6) #"\31 \0\0" "integer->bytes")
  (check-equal? (integer->bytes 6684672 24 8) (bytes 102 0 0) "integer->bytes"))

(define (integer->bytes int int-length bit-length)
  (if (= int-length bit-length)
      (bytes int)
      (bytes-append 
       (bytes (bitwise-bit-field int
                                 (- int-length bit-length)
                                 int-length))
       (integer->bytes 
        (bitwise-bit-field int
                           0
                           (- int-length bit-length))
        (- int-length bit-length)
        bit-length))))

;; appends padding bits to any string
(module+ test
  (check-equal? (bytes-length (append-len-bits
                               (append-padding-bits #"anymessage")
                               (bytes-length #"anymessage"))) 64 "length with padding")
  (check-equal? (append-padding-bits #"anymessage")
                #"anymessage\200\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                "padding"))

(define (append-padding-bits byte-str)
  (let* ((len (* (bytes-length byte-str) 8))
         (pad-len (remainder
                       (+ 448
                          (- 512 len))
                       512))
         (padding-len (if (zero? pad-len)
                          512
                          pad-len))
         (padding (bitwise-xor
                   (sub1 (expt 2 padding-len))
                   (sub1 (expt 2 (sub1 padding-len))))))
    (bytes-append byte-str (integer->bytes padding padding-len 8))))

;; convert big endian integer to little endian
(module+ test
  (check-equal? (be->le #x34FC2A07 32) #x072AFC34 "big endian -> little endian"))

(define (be->le int int-len)
  (if (zero? (- int-len 8))
      int
      (bitwise-ior
       (<<< int (- int-len 8) int-len)
       (be->le (>>> int 8 (- int-len 8))
               (- int-len 8)))))

;; appends length bits in format [low 32 bit][high 32 bit] to any string
(module+ test
  (check-equal? (append-len-bits #"abc" 12) #"abc`\0\0\0\0\0\0\0" "length bits")
  (check-equal? (append-len-bits #"abc" 0) #"abc\0\0\0\0\0\0\0\0" "length bits")
  (check-equal? (append-len-bits #"abc" (expt 2 64)) #"abc\0\0\0\0\0\0\0\0" "length bits")
  (check-equal? (append-len-bits #"abc" (sub1 (sub1 (expt 2 64)))) #"abc\360\377\377\377\377\377\377\377" "length bits"))

(define (append-len-bits byte-str len)
  (bytes-append
   byte-str
   (integer->bytes (be->le (* len 8) 64) 64 8)))

;; right shift with truncation
(module+ test
  (check-equal? (>>> #b0111 1 4) #b0011 ">>>")
  (check-equal? (>>> #b0111 2 4) #b0001 ">>>")
  (check-equal? (>>> #b0111 3 4) #b0000 ">>>")
  (check-equal? (>>> #b0111 4 4) #b0000 ">>>"))

(define (>>> int num-bits int-length)
  (bitwise-and (arithmetic-shift int (* -1 num-bits))
               (sub1 (expt 2 int-length))))

;; left shift with truncation
(module+ test
  (check-equal? (<<< #b0111 1 4) #b1110 "<<<")
  (check-equal? (<<< #b0111 2 4) #b1100 "<<<")
  (check-equal? (<<< #b0111 3 4) #b1000 "<<<")
  (check-equal? (<<< #b0111 4 4) #b0000 "<<<"))

(define (<<< int num-bits int-length)
  (bitwise-and (arithmetic-shift int num-bits)
               (sub1 (expt 2 int-length))))

;; circular left shift
(define (rotate-<<< int num-bits int-length)
  (bitwise-ior
   (<<< int num-bits int-length)
   (>>> int (- int-length num-bits) int-length)))

;; modulo addition
(define ((modulo-+ m) . xs)
  (remainder (apply + xs) m))
;; addition by modulo 2^32
(define modulo-2-32 (modulo-+ #x100000000))

;; curried round proc
(define ((round-proc aux-func) a b c d xk s i)
  (modulo-2-32 b 
               (rotate-<<< (modulo-2-32 a (aux-func b c d) xk (vector-ref T i))
                           s 32)))

;; returned function depends on round number
(define (round-num-proc round-num)
  (case round-num
    ((1) (round-proc F))
    ((2) (round-proc G))
    ((3) (round-proc H))
    ((4) (round-proc I))))

;; get X[k], like described in RFC 1321
;(module+ test
;  (check-equal? ((x<k> #"\0\1\2\3") 0) #x03020100 "x<k>")
;  (check-equal? ((x<k> #"\377\376\375\374") 0) #xFCFDFEFF "x<k>"))

(define ((x<k> byte-block) index)
  (let ((word (subbytes byte-block
                        (* index 4)
                        (* (add1 index) 4))))
    
     (bitwise-ior
      (bytes-ref word 0)
      (<<< (bytes-ref word 1) 8 32)
      (<<< (bytes-ref word 2) 16 32)
      (<<< (bytes-ref word 3) 24 32))
     ))

;; get index of X or get S
(define ((get-index lst) round num)
  (list-ref (list-ref lst (sub1 round)) num))

(define get-x-index (get-index X))
(define get-s (get-index S))

;; cyclically rotates list to the right by 1
(module+ test
  (check-equal? (rotate-right-1 (list 3 6 7 8)) '(8 3 6 7) "rotate list right by 1")
  (check-equal? (rotate-right-1 (list 8 3 6 7)) '(7 8 3 6) "rotate list right by 1")
  (check-equal? (rotate-right-1 (list 7 8 3 6)) '(6 7 8 3) "rotate list right by 1")
  (check-equal? (rotate-right-1 (list 6 7 8 3)) '(3 6 7 8) "rotate list right by 1"))

(define (rotate-right-1 lst)
  (let* ((rev-lst (reverse lst))
         (last-el (car rev-lst))
         (rev-cdr (cdr rev-lst)))
    (cons last-el (reverse rev-cdr))))

;; run one round chunk
(define (do-round-chunk byte-block abcd-list i max-i)
  (let* ((xk (x<k> byte-block))
         (round-num
          (add1
           (inexact->exact
            (truncate (/ i 16)))))         
         (a (list-ref abcd-list 0))
         (b (list-ref abcd-list 1))
         (c (list-ref abcd-list 2))
         (d (list-ref abcd-list 3)))
    (if (>= i max-i)
        abcd-list
        (let* ((x (xk (get-x-index round-num (remainder i 16))))
               (s (get-s round-num (remainder i 4)))
               (new-a ((round-num-proc round-num) a b c d x s i)))
          (do-round-chunk byte-block
                          (rotate-right-1 (list new-a b c d))
                          (add1 i)
                          max-i)))))

;; converts hex number to string with heading zeroes
(module+ test
  (check-equal? (hex->string #x0) "00" "hex->string")
  (check-equal? (hex->string #x1) "01" "hex->string")
  (check-equal? (hex->string #xF2) "f2" "hex->string"))

(define (hex->string hex-num)
  (if (<= hex-num #x0F)
      (string-append "0" (number->string hex-num 16))
      (number->string hex-num 16)))

;; converts list of hex numbers to human readable string
(module+ test
  (check-equal? (abcd-list->hex-string
                 '(#x12FC0A76 #x5EFB0036 #x90FA0A96 #x33EE0671))
                "760afc123600fb5e960afa907106ee33" "readable output"))

(define (abcd-list->hex-string abcd-list)
  (define (aux lst acc-str)
    (if (null? lst)
        acc-str
        (aux (cdr lst)
             (string-append
              acc-str
              (string-append
               (hex->string (>>> (<<< (car lst) 24 32) 24 32))
               (hex->string (>>> (<<< (car lst) 16 32) 24 32))
               (hex->string (>>> (<<< (car lst) 8 32) 24 32))
               (hex->string (>>> (car lst) 24 32)))))))
  (aux abcd-list ""))

;; transforms the whole message, block by block
(define (transform prep-byte-str abcd-list)
  (if (zero? (bytes-length prep-byte-str))
      (abcd-list->hex-string abcd-list)
      (transform
       (subbytes prep-byte-str 64)
       (map (lambda (x y) (modulo-2-32 x y))
            abcd-list
            (do-round-chunk
             (subbytes prep-byte-str 0 64)
             abcd-list 0
             (vector-length T))))))

;; main md5 procedure
;; tests are borrowed from rfc
(module+ test
  (check-equal? (md5 #"") "d41d8cd98f00b204e9800998ecf8427e" "MD5 hash of empty string")
  (check-equal? (md5 #"a") "0cc175b9c0f1b6a831c399e269772661" "MD5 hash of a")
  (check-equal? (md5 #"abc") "900150983cd24fb0d6963f7d28e17f72" "MD5 hash of abc")
  (check-equal? (md5 #"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
                "d174ab98d277d9f5a5611c2c9f419d9f" "MD5 hash of [A-Za-z0-9]"))

(define (md5 byte-str)
  (let* ((str-len (bytes-length byte-str))
         (prepared-str (append-len-bits (append-padding-bits byte-str) str-len)))
    (transform prepared-str (list word-A word-B word-C word-D))))
