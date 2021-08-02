# x86-emulator

x86-emulator is a simple proof-of-concept 32-bit x86 emulator written in [Rust](https://www.rust-lang.org/). It is an educational project with the goal of being able to run an unmodified, Linux ELF32 32-bit Hello World executable in a similar vein as [EPIC OS](https://github.com/nufflee/epic).

This project will only ever implement a tiny subset of the x86 ISA required to accomplish the goal (and likely a bit more).

## Building

### Dependencies
- Rust nightly
- nasm

Rust nightly is required due to the use of inline assembly in certain tests. This requirement will be alliviated in the future.

Once you have installed the dependencies, simply run:
```sh
$ make run
```

### Tests
In order to run the unit tests, use:
```sh
$ make test
```

## Resources
- [Intel x86 Instruction Set Developer's Manual](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf)
- [Felix Cloutier's x86 Instruction Reference website](https://www.felixcloutier.com/x86/)