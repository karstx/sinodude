# sinodude

A programming tool for SinoWealth 8051 microcontrollers.

## Warning

**This tool is experimental. Use at your own risk.**

SinoWealth microcontrollers have limited public documentation. This tool has been developed through reverse engineering and may not work correctly with all chip variants and all configurations.

## Supported Programmers

| Programmer | Description | Notes |
|------------|-------------|-------|
| sinodude-serial | Open-source Arduino Nano (ATmega328P or ATmega328PB) based programmer. See [firmware/README.md](firmware/README.md) for details. | Recommended |
| sinolink | The genuine SinoWealth SinoLink USB dongle (`258a:5063`) running its 8051 firmware. | 8051 parts only |

## Using the SinoLink dongle

Pick the backend with `-c sinolink`. The dongle has to be running its 8051 firmware (version block
byte `0x0d` bit 0); a dongle left in its bootloader (`258a:5007`) or running other firmware is
refused.

| Option | Effect |
|---|---|
| `--power 3v3` (default), `5v` | the dongle switches that supply on during entry |
| `--power external` | the board powers the target; the dongle connects on its own once it sees the rail above 1.9 V |
| `--link 4wire` (default), `1wire` | 4-wire ICP (TCK, TDI, TDO, TMS) or the single-wire link on the TDO pin, which only parts with the single-wire capability bit (`0x80000`) accept |
| `--power_on_time 3..27` | parameter byte 6, the wait before reset is released during entry (default 3) |
| `--use_reset_pin` | drive the reset pin during entry and always run a full entry |

```sh
sinodude read     -c sinolink -p sh68f90a --power 3v3 --flash out.hex
sinodude write    -c sinolink -p sh68f90a --power 5v  --flash firmware.hex
sinodude erase    -c sinolink -p sh68f90a --power 3v3
sinodude security -c sinolink -p sh68f90a --power 3v3 --write_protect 3
```

`sinodude sinolink` exposes the dongle below the part abstraction:

```sh
sinodude sinolink probe                       # version block, power state, stored parameter block
sinodude sinolink dump --part sh68f90a --addr 0x1000 --len 0x40 --region custom
sinodude sinolink raw  --req 0x15 --value 1 --len 2
```

### How a session runs

Every operation runs this sequence:

1. `0x00` version, then the 1 KiB parameter block is compared with the stored one (`0x11`) and, if
   bytes `0..0x3ef` differ, rewritten (`0x12` sector erase, `0x10`, `0x11` read-back, up to three
   rounds). The block is built field for field from the part's descriptor values and what the
   operation is about to do: the image (lengths, byte sums, CRC-16 and CRC-32), the option words,
   CID and S/N, the protection bitmap and passwords, the auto steps, sector selection and the build
   time. Each offset is named in `sinolink::field`. The dongle itself reads only ChipType, link,
   supply, power-on time, reset handling, the customer and product block addresses, the single-wire
   speed override and the erase delay.
2. Connect by power state (`0x15`): off gives a full entry (`0x40` sub 1: supply, reset, entry
   trains, mode `0x96`, link check); dongle-powered or externally powered gives a link check only
   (sub 4), falling back to `0x41` sub 0 and a full entry when that fails.
3. Customer key (`0x46`) for SecurityLevel 2 and above, zeros unless `--key` is given.
4. Identity: `0x40` bytes of the customer space at `CustomerID + 0x209`, whose first five must be the
   part number.
5. Reads (`0x44`) and writes (`0x42`) in `0x400`-byte chunks, each followed by `0x16`; erases
   (`0x45`) report their error in the reply.
6. `0x41` sub 0: supply off with a 300 ms discharge pulse. An externally powered target is left alone.

### Things that bite

**Erased flash reads `0x00`.** Programming only sets bits, so a security bit already burnt cannot be
cleared without a mass erase.

**A whole-chip erase rewrites part of the customer block itself.** After every erase except a sector
or E2 page, the dongle writes 17 zero bytes at the customer block + 10, which is the start of the
security record. On ChipType 7 parts other than JTAG ID `3213` the host also rewrites code option
word 1 at the customer block + `0x100` straight after the erase, and picks a wider erase when the
stored ISP or E2 size in that word differs from the one being written: type 4 (`0x2D`) or 5
(`0xC3`, code, ISP and E2) instead of 1 (`0x4B`).

**A failed link check after a read is silent.** It leaves an error behind that makes every later
write return without touching the target while `0x16` still reports 0. The driver runs a link check
(`0x40` sub 4) before every batch of writes and erases, which clears it.

**Two requests reboot the dongle**: `0x04` into the CMSIS-DAP image and `0x3f` into the bootloader.
`sinolink raw` refuses both.
