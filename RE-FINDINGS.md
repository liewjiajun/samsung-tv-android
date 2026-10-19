# RE-FINDINGS.md — the actual mechanics, from primary sources

Started 2026-10-19. This is the reverse-engineering record: what the mechanisms
actually are, what they give us, and what stands between us and a Tizen that
behaves like Android.

Sources are checked out in `re/` (two public root projects). Everything below is
read from their code/docs, not inferred.

---

## 1. The chain, end to end

Four separate boundaries have to be crossed. Each is a distinct problem with a
distinct solution. Conflating them is what makes this look impossible.

| # | Boundary | Mechanism used | Status |
|---|---|---|---|
| 1 | Reach a shell as `sdk` (uid 901) | SDB package-name command injection, `SVE-2025-50109` | public, works |
| 2 | `sdk` → `uid 0` | archive-root: mount-namespace trust-anchor substitution | public, works |
| 3 | root → **execute our own code** | UEP status word patch in kernel memory | model-specific |
| 4 | execute → **persist** | none on-device; host controller re-arms | the real wall |

### 1.1 Foothold — the injection

Developer Mode opens SDB on TCP 26101. A normal shell request is refused, but the
internal command is accepted:

```
0 appinstall tpk <package-name>
```

Samsung's install path interpolates the package filename into a shell command
without quoting. Backtick substitution evaluates:

```
new2.tpk`printf${IFS}%s${IFS}<B64>|base64${IFS}-d|bash`.tpk`
```

`${IFS}` supplies spaces, base64 dodges quoting. Result: command execution as
`uid=901(sdk)` with the **Tizen System SMACK label**.

### 1.2 sdk → root — archive-root

The clever part, and the reason this works model-independently. `sdbd-tarlauncher`
is a setuid-ish helper that extracts an archive. It trusts two things by path:

1. `/usr/share/sdbd/public.pem` — the verification key
2. `/etc/passwd`

Because the process holds `CAP_SYS_ADMIN` + `CAP_SETGID`, it can:

1. `unshare(CLONE_NEWNS)` — new mount namespace, so we own the mount table
2. `mount --make-rprivate /` — detach from the real tree
3. bind-mount our own `public.pem` over the verification key
4. bind-mount our own `passwd` over `/etc/passwd` (with `owner:x:0:0`)
5. run `sdbd-tarlauncher --to-command=/bin/sh`

The launcher now verifies against *our* key and reads *our* passwd. It extracts as
a user that resolves to uid 0.

**Key insight:** no memory corruption. It's a trust-anchor substitution — the
helper asks the filesystem who it should trust, and we changed the answer. That's
why it works across models.

### 1.3 root → executing our code — UEP

This is the boundary that matters most for our goal, and the one that gets
misunderstood.

**UEP is a kernel-side `execve` check.** Getting uid 0 does *not* let you run your
own ELF. The kernel refuses.

Two ways past it, both documented:

**a) The signed host — this is the one that works.** Samsung's own
`/usr/bin/dotnet` loads an uploaded managed assembly **as data** while UEP stays
enabled. It is a signed binary doing the loading, so there is no unsigned ELF to
check. P/Invoke supplies raw syscalls. This is the bootstrap path the public
research uses for all their payloads.

**b) Patch the UEP status word itself.** The QN90F payload does this:

```c
NeighborhoodPhysical = 0x20b58020   // known-good words for validation
StatusPhysical       = 0x20b58030   // the flag: 1 = UEP on, 0 = off
```

It validates 7 neighbouring words first — pubkey pointers and a `0/1` flag — then
writes `0`. That neighbourhood check is the interesting engineering: it refuses to
write unless the surrounding memory matches what the firmware is supposed to look
like, so a wrong address can't silently corrupt something else.

**This is the address that must be re-derived per model and per firmware.** It is
found by scanning the kernel image for the validation pattern.

#### Correction: memfd does NOT bypass UEP

An earlier version of this file claimed that `memfd_create` + `execveat` bypasses
UEP because "there is no path for the check to inspect." **That is wrong.**

The researchers tested it explicitly:

> "Direct ELF loading and anonymous `fexecve` were both rejected while UEP was
> enabled."
> — `samsung-tv-root/docs/research-notes/QN90F_REPRODUCTION.md`

So UEP does not inspect a *path*. It inspects the **file contents** at exec time.
Removing the path does not remove the check.

Why the confusion happened: `re/uep-analogue-test.sh` proves that memfd defeats a
**path-based** denial, such as a `noexec` mount. That is a true result about a
different mechanism. It says nothing about UEP, which is content-based. The test
was sound; the inference drawn from it was not.

**Consequence:** `toolkit/memfd_exec.py` is useful for defeating *path*-based
exec restrictions, and useless against UEP. Do not count it as a UEP bypass.

### 1.4 Getting the physical-memory primitive

To write kernel memory you need an arbitrary-physical-write. Two different bugs,
by generation:

- **QN90B (32-bit):** `/dev/sdp_pqe_fdet` is world-writable and its `mmap` handler
  does `remap_pfn_range(vma, vm_start, vma->vm_pgoff, ...)` with **no validation**
  that `vm_pgoff` names an FDET buffer. Any PFN maps. Unrestricted `/dev/mem`.
- **QN90F (Mali-G510):** CVE-2025-0072, a use-after-free in Mali command-stream
  USER_IO pages, turned into a page-table alias. Free the USER_IO pages, get them
  reallocated as a live GPU L3 page table, keep a writable CPU mapping to it.
  Temporarily swap a PTE for `physical_page | 0x64b`, flush, read/write through a
  compute shader. Restore after each op.

Both end at the same place: read/write any physical page.

### 1.5 Escalation to uid 0 once you can write memory

Not a simple cred overwrite — kernel pointers and layout vary. The technique:

1. `setresuid(901,901,901)` per thread → each thread gets a *private* cred object
2. `PR_SET_NAME` with a unique 15-byte tag
3. Scan physical RAM for that tag (the `task_struct.comm` field)
4. Validate each hit: 16-byte comm with zero padding, matching PID nearby,
   plausible `real_cred`/`cred` pointers just before comm, both pointing into
   known RAM range
5. Write `901` across the eight credential identity words
   (`uid, gid, suid, sgid, euid, egid, fsuid, fsgid`)

---

## 2. The persistence problem — and why it defines our architecture

This is the finding that shapes everything.

**Verified mount topology (2026 QA55QEF1AULXL):**

```
/      vdfs ro        <- read-only
/tmp   tmpfs rw       <- gone on reboot
/opt   vdfs rw        <- WRITABLE and PERSISTS
/home/owner/share/tmp/sdk_tools   world-writable
```

So:

- **Files persist** in `/opt`.
- **UEP resets to stock on every reboot.** Authorisation does not persist.
- No writable systemd unit directory exists.

The original authors concluded on-device persistence is "provably impossible" on
that target, and shipped a **host-side controller that re-arms root after each
reboot**.

**This is the central design constraint for our goal.** Any "Android-like" layer
must either:

- **A.** Be re-established by an external controller on boot (works today,
  requires a always-on host), or
- **B.** Find a boot-time execution path that survives — which means influencing
  *what the boot chain loads*, i.e. signed content, or
- **C.** Live somewhere that legitimately starts at boot: a **signed Tizen app**
  that auto-launches (Tier 2). TizenBrew is precedent for a sanctioned app that
  installs and runs things.

**C is the underexplored one.** A signed `.tpk` with an auto-launch privilege runs
at boot, inside the sandbox, forever, without a host. Its limitation is privilege,
not persistence. Combining C (persistence, low privilege) with 1-3 (privilege, via
a re-arm) is the shape that could actually hold.

### 2.1 A hard gotcha worth recording

Assemblies under `/tmp` **refuse to load**:

```
/usr/bin/dotnet /tmp/x/SamsungTvArchiveRoot.dll   # fails
/usr/bin/dotnet /opt/usr/....dll                  # works
```

So staging under `/opt` is mandatory for dotnet payloads. This is exactly the kind
of detail that costs a day if you don't know it.

---

## 3. What this means for "make Tizen into Android"

The goal as stated: customise Tizen so heavily it is essentially another Android.

Given the mechanics, the honest decomposition:

### 3.1 What is achievable

| Capability | Mechanism | Confidence |
|---|---|---|
| Persistent writable userspace in `/opt` | already true | high |
| Run our own native/ARM binaries | **signed dotnet host** loading a managed DLL (no UEP patch), or UEP memory patch for true native ELF | high — dotnet path is publicly proven |
| Debian userland alongside Tizen | chroot into `/opt` after UEP disable | medium-high |
| Replace Tizen's launcher/home UI | signed `.tpk` replaces the app surface | medium |
| Android *apps* (APK runtime) | needs binder + a container | **the question** |
| Full Android look/feel | a launcher + our own app set | medium |
| Boot-time autostart without host | signed app with autostart privilege | medium |

### 3.2 Cloud/TV-gaming-style "Android feel" without Android

Worth naming because it may satisfy the actual want: a custom launcher, our own
app grid, controller navigation, sideloaded web apps and native binaries. That is
**Tier 2 pushed hard** — no APKs, but a TV that behaves like a custom Android TV
box. This needs no root, no UEP work, no brick risk.

### 3.3 The binder question — still the gate

For real APK support, Android userspace needs binder. Three outcomes:

1. **binder present** in the kernel → container path viable. Best case.
2. **modules loadable, unsigned allowed** → build binder against the exact
   vermagic. `re/analyze-kernel.py` extracts it.
3. **modules signed/forced, or no modules** → cannot add binder at runtime.
   Would need a kernel rebuild, which needs boot-chain access, which is closed.

**Outcome 3 is not necessarily fatal** — option C above (launcher + native apps)
still delivers a heavily customised TV. But it kills APK support.

---

## 4. Immediate next steps, in dependency order

1. **Get a kernel image for the target model.** Firmware mirrors are reachable
   (samfrew, firmware.mobi, samfw all return 200). Run `analyze-kernel.py` on it.
   This answers binder *offline*. No TV, no risk.
2. **If config is embedded** → verdict is immediate and decisive.
3. **If not** → `strings`/pattern-scan the decompressed payload for binder symbols
   and the UEP neighbourhood pattern; derive the UEP address for that firmware.
4. **Prove the UEP patch on the armv7 VM** — not the TV. Build the equivalent
   patch against the emulated kernel, verify it writes the right word and that an
   unsigned binary then executes.
5. **Only then** touch hardware, and only the read-only probe first.

---

## 5. Tooling built for this

| Tool | Purpose | Validated? |
|---|---|---|
| `re/analyze-kernel.py` | kernel image → binder/container verdict + vermagic | **yes**, against a known-answer armv7 control |
| `toolkit/tizen-capability-probe.sh` | live TV capability probe, read-only | on armv7; not on a TV |
| `toolkit/memfd_exec.py` | run unsigned payload from memory — defeats PATH-based exec denial | self-test on host + qemu-arm; **does NOT bypass UEP** |
| `vm/tvvm.sh` | offline armv7 lane | yes, end to end |

`analyze-kernel.py --selftest` checks itself against the Debian armv7 kernel whose
properties are independently known (namespaces/cgroups/overlay present, binder
absent). If it ever disagrees with that control, the tool is wrong.

---

## 6. Ethics and scope

Everything here is read from public research on hardware the authors owned. This
project is for a TV we own. The foothold is a disclosed vulnerability
(`SVE-2025-50109`); the escalation is public. Nothing novel is being exploited.

The rule from `BRICK-RISK.md` still governs: **no write to the boot chain.**
