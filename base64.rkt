;;; Program: My own base64 encoding/decoding implementation
;;; Author: Dmitry A. Paramonov (c) 2013
;;; License: BSD

;;;TODO: 
;;; 1. Extend to baseNN module which will be able to encode/decode in/from base32 and base16 too.
;;; 2. Optimize the code.

#lang racket

(require rackunit)

(provide b64encode b64decode)
;; Globals: base64 alphabet and padding char
(define b64alphabet #"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
(define padding-char #"=")

;; a variation of map function for bytes list
(define (bytes-map proc bytes-str)
  (list->bytes
   (map proc
        (bytes->list bytes-str))))

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

;; truncates zero bytes from byte list
(define (trunc bytes-str)
  (list->bytes
   (filter (lambda (el)
             (not (equal? el 0)))
           (bytes->list bytes-str))))

;; returns an index of symbol in an alphabet
(module+ test
  (check-equal? (index-of #"A" b64alphabet) 0 "index-of helper"))

(define (index-of b alph)
  (cond ((zero? (bytes-length alph)) 0)
        ((bytes=? b (bytes (bytes-ref alph 0)))
         0)
        (else (+ 1 (index-of b (subbytes alph 1))))))

;; base64 encoding
(module+ test
  (check-equal? (b64encode #"") #"" "b64encode")
  (check-equal? (b64encode #"f") #"Zg==" "b64encode")
  (check-equal? (b64encode #"fo") #"Zm8=" "b64encode")
  (check-equal? (b64encode #"foobar") #"Zm9vYmFy" "b64encode"))

(define (b64encode bytes-str)
  (define (encode-octets octs)
    (let* ((len (bytes-length octs))
           (full-int (bytes->integer octs 8))
           (int (bytes->integer
                 (bytes-append octs (make-bytes (- 3 len))) 8)))
      (cond ((= len 0) (make-bytes 0))
            ((= len 1)
             (bytes-append
              (bytes
               (bytes-ref b64alphabet (bitwise-bit-field int 18 23))
               (bytes-ref b64alphabet (bitwise-bit-field int 12 18)))
              padding-char padding-char))
            ((= len 2)
             (bytes-append
              (bytes
               (bytes-ref b64alphabet (bitwise-bit-field int 18 23))
               (bytes-ref b64alphabet (bitwise-bit-field int 12 18))
               (bytes-ref b64alphabet (bitwise-bit-field int 6 12)))
              padding-char))
            ((= len 3)
             (bytes-map (lambda (el)
                          (bytes-ref b64alphabet el))
                  (integer->bytes full-int 24 6))))))
  (if (< (bytes-length bytes-str) 3)
      (encode-octets bytes-str)
      (bytes-append
       (encode-octets (subbytes bytes-str 0 3))
       (b64encode (subbytes bytes-str 3)))))

;; base64 decoding
(module+ test
  (check-equal? (b64decode #"") #"" "b64decode")
  (check-equal? (b64decode #"Zg==") #"f" "b64decode")
  (check-equal? (b64decode #"Zm8=") #"fo" "b64decode")
  (check-equal? (b64decode #"Zm9vYmFy") #"foobar" "b64decode"))

(define (b64decode bytes-str)
  (define (decode-octets octs)
    (let ((indices (list->bytes (map (lambda (el)
                                       (if (equal? el 61)
                                           0
                                           (index-of (bytes el) b64alphabet)))
                                     (bytes->list octs)))))
      (trunc
       (integer->bytes (bytes->integer indices 6) 24 8))))
  (cond ((not (zero? (remainder (bytes-length bytes-str) 4))) (display "ERROR: wrong base64 encoding"))
        ((<= (bytes-length bytes-str) 0)
         (make-bytes 0))
        (else (bytes-append 
               (decode-octets (subbytes bytes-str 0 4))
               (b64decode (subbytes bytes-str 4))))))
