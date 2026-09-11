# Externally encoded LHA conformance fixtures

These `.bin` files are **complete level-0 LHA archives**, including the header
and terminator. Each contains `pattern.bin`, a 394211-byte deterministic input
constructed below. The input and resulting fixture data are synthetic work of
this project, distributed under its MIT OR Apache-2.0 license. No original media,
external test corpus, or encoder implementation is included.

All five archives were produced by the external jLHA encoder, through its public
archive API. LH1 exercises adaptive Huffman coding; LH4–LH7 exercise static
Huffman coding with explicitly encoded, non-singleton trees. The first static
block has 2555 tokens and a 14-entry code-length alphabet, instead of the zero
count used for a singleton tree. The input includes every byte value, varied
runs, repeated substrings, and enough output to cross decoder buffer and ring
boundaries. This is targeted coverage, not exhaustive format validation.

`tests/conformance.rs` pins every archive hash, regenerates the expected input
bytes without compression code, compares the entire recovered file, and checks
that an insufficient output budget is refused. Tests need neither Java nor any
external executable. The older deliberately narrow patterns remain under
`../synthetic/` for malformed-stream and initial-dictionary regression coverage.

## Encoder and source identity

- [OrangeSignal CSV source](https://github.com/orangesignal/orangesignal-csv/tree/60432ca09f2fd3884f75246d4b51eb44666e8e8f),
  revision `60432ca09f2fd3884f75246d4b51eb44666e8e8f`, version
  `2.2.2-SNAPSHOT` (seven commits after tag `2.2.1`). Only its
  `src/main/java/com/orangesignal/jlha/` package was compiled.
- jLHA is by Michel Ishizuka, under the two-clause BSD terms in
  [the pinned license](https://github.com/orangesignal/orangesignal-csv/blob/60432ca09f2fd3884f75246d4b51eb44666e8e8f/JLHA-LICENSE.txt).
  [JLHA-LICENSE.txt](JLHA-LICENSE.txt) retains that notice for the documented
  tool, with line endings and trailing whitespace normalized. It does not change the license of our synthetic fixture data.
- Source tarball SHA-256:
  `98026a435e5fba7d042774b4596376fb80c8a5263fad13449a8b028037f33bf9`.
- Upstream unmodified license file SHA-256:
  `3b1e6adeb6cd5f98dee5cb69b1b2c3c17bb94415e36ebd0f7fa3dc9b81a218bf`.
- Generation environment: Eclipse Temurin OpenJDK `25.0.2+10-LTS`, Linux x86_64;
  Java timezone forced to UTC, archive timestamp `2000-01-01T00:00:00Z`.

## Reproduce

Run in a fresh temporary working directory, outside the repository. The Java
snippet is an external API driver, with no compression algorithm. Do not make
fixture generation part of `cargo test` or add an in-tree encoder.

```sh
curl -fL https://codeload.github.com/orangesignal/orangesignal-csv/tar.gz/60432ca09f2fd3884f75246d4b51eb44666e8e8f -o encoder.tar.gz
printf '%s\n' '98026a435e5fba7d042774b4596376fb80c8a5263fad13449a8b028037f33bf9  encoder.tar.gz' | sha256sum -c -
mkdir source classes output
tar -xzf encoder.tar.gz -C source --strip-components=1
javac -encoding UTF-8 -d classes source/src/main/java/com/orangesignal/jlha/*.java
python3 - <<'INPUT'
from pathlib import Path
block = bytes((i*i + 17*i + i//7) % 256 for i in range(4096))
pattern = b''.join(bytes([n]) * (n % 31 + 1) + block[n:n+2048] + block
                   for n in range(64))
Path('pattern.bin').write_bytes(pattern)
INPUT
cat > LhaFixtures.java <<'JAVA'
import com.orangesignal.jlha.*;
import java.nio.file.*;
import java.util.*;
public class LhaFixtures {
    public static void main(String[] args) throws Exception {
        byte[] input = Files.readAllBytes(Path.of(args[0]));
        for (String method : new String[]{"lh1", "lh4", "lh5", "lh6", "lh7"}) {
            LhaHeader header = new LhaHeader("pattern.bin", new Date(946684800000L));
            header.setHeaderLevel(0);
            header.setCompressMethod("-" + method + "-");
            try (LhaOutputStream out = new LhaOutputStream(Files.newOutputStream(Path.of(args[1], method + ".bin")))) {
                out.putNextEntry(header);
                out.write(input);
                out.closeEntry();
            }
        }
    }
}
JAVA
javac -cp classes -d classes LhaFixtures.java
java -Duser.timezone=UTC -Dfile.encoding=UTF-8 -cp classes LhaFixtures pattern.bin output
sha256sum pattern.bin output/*.bin
```

## Exact bytes and independent checks

Input and every decoded output SHA-256:
`0c2b8a1b2a2bfc561ca8a83e05190c3753675978729a95a9bd6c20df65fa8b5b`.

| Archive | Archive bytes | Archive SHA-256 |
| --- | ---: | --- |
| `lh1.bin` | 12106 | `b3d46520a5c971959b543330b22ed66bbcd0dbdfee4ba18ff352a8d542e7c9f5` |
| `lh4.bin` | 3486 | `a480e2115c9596e93c855ad955004e9875bc01befd24297ba3990bb17e512437` |
| `lh5.bin` | 3486 | `48891dcdb4a9d12b5873072ae60570e55f6f4325f2d1d0c4cfbfbbda5b48a7e5` |
| `lh6.bin` | 3486 | `dd7663f706bee810d76dd755b56552261733a4adf70c870002eeb9a6ec648a15` |
| `lh7.bin` | 3486 | `92a801e820e6409e35dc05c571f9668b6982011cfdf1c739af346946012a5792` |

Checked on 2026-09-11 with the following decoders, comparing **all output bytes**
to the generated input, as well as their SHA-256 values:

- **LH1 and LH4–LH7:** [LHa for UNIX](https://github.com/jca02266/lha/tree/16619b066b189ef289bb8b07b37d1c38d550da99),
  version `1.14i-ac20260723`, revision
  `16619b066b189ef289bb8b07b37d1c38d550da99`. Its original license is documented
  in the upstream `man/lha.n`; no Unix LHa code or executable is redistributed.
  Source tarball SHA-256:
  `171cb8bc09ee9610b09d7366ed5e5459972d790937fbcce385e7cb89d1910226`.
  Built directly from the unmodified source files listed in `src/Makefile.am`
  using GCC `16.2.1 20260819`, GNU99, `-O2`, Linux system-library feature
  definitions and `SUPPORT_LH7=1`. The resulting executable SHA-256 was
  `682c10a3955b1013dc1a64d16812c967a66b73f1534f785d795c1fb49f740e5f`.
  The upstream-supported build is `autoreconf -is`, `./configure`, `make`;
  executable hashes depend on the build environment, archive hashes do not.
- **LH4–LH7:** 7-Zip `26.02` (x64), release date `2026-06-25`.
  This build does not decode LH1, so it was not used as an LH1 oracle.

With the built Unix LHa on `PATH`, repeat the byte comparisons in the temporary
working directory above:

```sh
for method in 1 4 5 6 7; do
    lha pq "output/lh${method}.bin" > "unix-lh${method}.decoded"
    cmp pattern.bin "unix-lh${method}.decoded"
done
for method in 4 5 6 7; do
    7z x -so "output/lh${method}.bin" > "7z-lh${method}.decoded"
    cmp pattern.bin "7z-lh${method}.decoded"
done
```

These checks use decoders outside delharc's implementation family; the
production decoder's own result, or Lhasa's related implementation, is not
counted as independent verification. No claim is made that unrelated
implementations must agree on every malformed or ambiguous LHA stream.
