# uncockblocker
solves the cockblock challenge on [cock.li](https://cock.li).

## why?
i was bored while my browser solved it. completed this before it was done so uhh worth it?

## how?
i have no idea how it actually works cause i'm horrible at math but i think it generates password hashes using argon2 and then compares the output hash using some math to a predetermined difficulty number.

## usage?
build like any other rust project, then just run:
```bash
uncockblocker <CHALLENGE>
```
or if you want to try the half broken multithreaded version:
```bash
uncockblocker --mt <CHALLENGE>
```