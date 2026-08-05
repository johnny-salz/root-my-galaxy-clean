# Root My Galaxy: A53 kit

This kit gives shell root, then live-loads KernelSU on one checked stock build:

`SM-A536E / A536EXXSNGZG3 / 5.10.237-android12-9-31999025-abA536EXXSNGZG3`

No boot unlock. No flash. Root is lost on reboot.

Live check: one clean reboot test reached shell root, loaded the final v3.2.5
(`32525`) KernelSU helper, and passed `/system/bin/su -c id`. The Manager showed
`Working <LKM>`, `32525-2`.

Read [TUTORIAL.md](TUTORIAL.md). See [PORTING.md](PORTING.md) before adapting to a new phone. See [PROVENANCE.md](PROVENANCE.md) before any port.

This can crash the phone. Bad target data can write to a bad kernel address.

Use it only on a phone you own. Back up data first.
