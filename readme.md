# Portfolio

**This repo is a work in progess**

This is a collection of writeups that I wish to display. Each folder in `chals`
corresponds to a single challenge. Writeups are seperated by vulnerability 
class. Each writeup has tags associated with it such as architecture, where the
challenge originated, and other terms I think are important. **this is not a
complete list of my work**. A lot of the challenges I have completed are active 
on `hackthebox` (I am not allowed to publish those writeups until the 
challenges are archived). For a complete portfolio please send me a message.

## sbof.ko

Check out my 
[series on kernel module development and exploitation](https://joe-hilbert.gitbook.io/public-portfolio/content/sbof.ko).

## Vulnerability Classes

### Heap Buffer Overflow

##### [Dream Diaries: Chapter 1](chals/dream_diary_chapter_1/readme.md)

    Arch: x86_64
    Security Measures
        - aslr
        - NX
        - stack canary
    Other tags
        - hackthebox
        - pwnc

### Type Confusion

##### [handout](chals/handout/readme.md)

    Arch: x86_64
    Security Measures
        - seccomp
        - Partial RELRO
        - aslr
    Other tags
        - idekctf2021

### Stack Buffer Overflow

##### [integer\_calc](chals/integer_calc/readme.md)

    Arch: x86_64
    Security Measures
        - Partial RELRO
        - NX
        - PIE
        - aslr
    Other tags
        - idekctf2021
        - pwnc
