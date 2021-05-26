# Crystal Lang CMAC

[![CI](https://github.com/spider-gazelle/cmac/actions/workflows/ci.yml/badge.svg)](https://github.com/spider-gazelle/cmac/actions/workflows/ci.yml)

Crystal implementation of the Cipher-based Message Authentication Code (CMAC) as defined in [RFC4493](http://tools.ietf.org/html/rfc4493), [RFC4494](http://tools.ietf.org/html/rfc4494), and [RFC4615](http://tools.ietf.org/html/rfc4615). Message authentication codes provide integrity protection of data given that two parties share a secret key.

```crystal
key = Random.new.random_bytes(16)
message = "attack at dawn"
cmac = CMAC.new(key)
cmac.sign(message)
 => Bytes[246, 184, 193, 76, 93, 115, 191, 26, 135, 60, 164, 161, 90, 224, 102, 170]
```

Once you've obtained the signature (also called a tag) of a message you can use CMAC to verify it as well.

```crystal
tag = Bytes[246, 184, 193, 76, 93, 115, 191, 26, 135, 60, 164, 161, 90, 224, 102, 170]
cmac.valid_message?(tag, message)
 => true
cmac.valid_message?(tag, "attack at dusk")
 => false
```

CMAC can also be used with a variable length input key as described in RFC4615.

```crystal
key = "setec astronomy"
message = "attack at dawn"
cmac = CMAC.new(key)
cmac.sign(message)
 => Bytes[92, 17, 144, 230, 145, 178, 196, 130, 96, 144, 166, 236, 58, 14, 28, 243]
```
