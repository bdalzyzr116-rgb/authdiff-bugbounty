# AuthDiff

**A differential authorization discovery framework for authorized bug bounty & pentests.**
Hunts broken access control (BOLA / IDOR, BFLA, mass-assignment) and single-use state
races using **deterministic canary / invariant oracles** — designed for **0% false
positives by construction**.

> ⚠️ **Authorized use only.** AuthDiff is a discovery / proof-of-concept tool. Use it
> exclusively against targets you are explicitly permitted to test (your own systems or
> an in-scope bug bounty program). Every network command requires the `--authorized`
> flag as a conscious confirmation of scope.

---

## English

### Why it exists
Vulnerability scanners treat each request in isolation, so they are blind to
**authorization** — a *relation* between an identity, an object, and a capability. When
user A requests `/orders/8213` and gets `200 OK`, the response looks identical whether or
not the order belongs to A. Scanners have no ground truth of ownership, so they either
miss the bug or drown you in false positives.

AuthDiff flips the problem: instead of *inferring* ownership, it **injects** it. It plants
**self-authenticating canary tokens** (HMAC-bound to their owner) into each identity's
private data, then replays traffic across identities. Finding one identity's canary inside
another identity's response is an **unforgeable cryptographic proof** of a cross-tenant
leak. Detection becomes an equality check, not a guess.

### Key features
| Feature | What it gives you |
|---|---|
| 🔐 **Self-authenticating canaries** | HMAC-bound tokens; a valid foreign canary in a response is mathematical proof of a leak → **0% false positives**. |
| 🔀 **Cross-identity differential engine** | Replays every object-referencing request under every *other* identity (+ anonymous) — complete over the observed surface. |
| 🎯 **Deterministic oracles** | BOLA/IDOR (I1), and extensible to BFLA (I2) and mass-assignment / BOPLA (I3) via the same canary math. |
| ⚡ **Single-packet HTTP/2 racer** | Coalesces N requests into one TCP segment to expose TOCTOU windows with ~0 jitter; a numeric invariant (`successes ≤ capacity`) decides the verdict. |
| 🛡️ **Scope Governor** | Hard host allowlist, token-bucket rate limiter, concurrency cap, kill-switch, and a required `--authorized` gate. |
| 📥 **HAR ingestion** | Feed captured traffic per identity straight from a browser/Burp HAR export. |
| 🧪 **Offline self-test** | `selftest` proves the oracle is sound with zero dependencies and no target. |

### How it works
```
1) seed   → each identity writes a fresh canary into its OWN private field (non-destructive)
2) run    → replay object-referencing requests under every OTHER identity; the oracle
            scans responses for foreign canaries and emits only PROVEN findings
3) race   → (optional) single-packet burst to confirm a single-use limit bypass
```

Authorization correctness is expressed as set-theoretic invariants that must always hold:
```
I1  Horizontal (BOLA/IDOR):     Reach(i) ∩ Priv(j) = ∅     for all i ≠ j
I2  Vertical  (BFLA):           privileged capability c ∉ Cap(i)  for unauthorized i
I3  Property  (BOPLA/mass-assign): WritableFields(i,E) ⊆ IntendedFields(E)
```
A finding is emitted **iff** a canary witness breaks an invariant.

### Install
```bash
pip install "httpx[http2]" h2      # only needed for seed/run/race
# `selftest` runs on the Python standard library alone
```

### Usage
```bash
# 1) Prove the core is sound (no target needed)
python3 authdiff.py selftest

# 2) Edit config.json — two identities (different owners/tenants), in an authorized scope
cp authdiff.config.example.json config.json

# 3) Seed a canary into each identity's own private field
python3 authdiff.py seed --config config.json --authorized

# 4) Run the differential access-control test (prints only canary-proven findings)
python3 authdiff.py run  --config config.json --authorized

# Alternative: ingest captured traffic per identity instead of writing "observed" by hand
python3 authdiff.py run  --config config.json --har alice=alice.har --har bob=bob.har --authorized

# 5) (optional) Confirm a single-use limit bypass via the single-packet racer
python3 authdiff.py race --config config.json --authorized
```

### Notes that matter
- The HMAC secret is persisted to `./.authdiff_secret` so `seed` and `run` share it. Keep
  it in the same directory between commands (a different secret ⇒ canaries won't validate).
- The single-packet racer needs **HTTPS (HTTP/2 over TLS)**; the normal `run` works over
  HTTP/1.1 or h2.
- You need **at least two identities** — the test is differential by nature.

### Roadmap
- Full `bfla` / `bopla` subcommands (I2 / I3 oracles)
- Pipeline integration with a continuous attack-surface differ (DeltaHunter)
- Proof-carrying report export (Markdown / HackerOne-ready)

### Disclaimer
This project is for **authorized security testing and education only**. You are solely
responsible for how you use it. Do not test systems you do not own or lack explicit written
permission to test. No warranty. Discovery / PoC only — it ships no weaponized exploits.

### License
MIT — see [LICENSE](LICENSE).

---

## العربية

### ليه الأداة دي موجودة
الماسحات (scanners) بتتعامل مع كل request لوحده، فبتبقى عمياء عن **الصلاحيات** — اللي هي
علاقة بين **هوية** و**object** و**قدرة**. لما المستخدم A يطلب `/orders/8213` ويرجعله
`200 OK`، الرد شكله واحد سواء الأوردر بتاعه ولا لأ. الماسح معندوش أي مصدر حقيقة عن الملكية،
فإما بيفوّت الثغرة أو بيغرقك في false positives.

AuthDiff بتقلب المعادلة: بدل ما **تخمّن** الملكية، بتـ**زرعها**. بتحط **canary tokens
موثِّقة لنفسها** (مربوطة بمالكها عن طريق HMAC) جوه البيانات الخاصة لكل هوية، وبعدين تعيد
إرسال الترافيك عبر الهويات. لو canary بتاع هوية ظهر في رد هوية تانية → ده **دليل تشفيري لا
يُزوَّر** على تسريب بيانات عبر الحدود. الاكتشاف بقى مقارنة مساواة، مش تخمين.

### أهم المميزات
| الميزة | بتديك إيه |
|---|---|
| 🔐 **canaries موثِّقة لنفسها** | توكنات مربوطة بـ HMAC؛ ظهور canary صالح لهوية تانية في الرد = دليل رياضي على التسريب → **صفر false positives**. |
| 🔀 **محرك تفاضلي عبر الهويات** | بيعيد كل request بيشير لـ object تحت كل هوية *تانية* (+ anonymous) — تغطية كاملة للسطح المرصود. |
| 🎯 **أوراكل حتمية** | BOLA/IDOR (I1)، وقابلة للتوسّع لـ BFLA (I2) وmass-assignment/BOPLA (I3) بنفس رياضيات الـ canary. |
| ⚡ **single-packet على HTTP/2** | بيجمع N من الطلبات في TCP segment واحد لكشف نوافذ الـ TOCTOU بأقل jitter؛ والحكم بأوراكل رقمي (`نجاحات ≤ السعة`). |
| 🛡️ **Scope Governor** | allowlist صارم للنطاق + token-bucket rate limit + سقف تزامن + kill-switch + بوابة `--authorized` إجبارية. |
| 📥 **استيراد HAR** | لقّم الأداة ترافيك متسجّل لكل هوية مباشرة من HAR بتاع المتصفح أو Burp. |
| 🧪 **self-test أوفلاين** | أمر `selftest` بيثبت سلامة الأوراكل من غير أي تبعيات ولا تارجت. |

### إزاي بتشتغل
```
1) seed → كل هوية بتكتب canary جديد في الحقل الخاص بيها هي (من غير تدمير)
2) run  → بتعيد الطلبات اللي بتشير لـ objects تحت كل هوية تانية؛ والأوراكل بيفحص الردود
          وبيطلع النتائج المثبتة بالـ canary بس
3) race → (اختياري) دفعة single-packet لتأكيد تجاوز مورد أحادي الاستخدام
```

صحّة الصلاحيات متعبَّر عنها كـ invariants مجموعية لازم تفضل صحيحة دايمًا:
```
I1  أفقي (BOLA/IDOR):      Reach(i) ∩ Priv(j) = ∅     لكل i ≠ j
I2  رأسي (BFLA):           القدرة المميّزة c ∉ Cap(i)  لأي i غير مصرّح
I3  الحقول (BOPLA):        WritableFields(i,E) ⊆ IntendedFields(E)
```
النتيجة بتطلع **فقط لو** فيه canary كسر أحد الـ invariants.

### التثبيت
```bash
pip install "httpx[http2]" h2      # محتاجها بس لـ seed/run/race
# أمر selftest بيشتغل بمكتبة بايثون القياسية لوحدها
```

### طريقة الاستخدام
```bash
# 1) اثبت إن النواة سليمة (من غير تارجت)
python3 authdiff.py selftest

# 2) عدّل config.json — هويتين (owners/tenants مختلفين) في نطاق مصرّح بيه
cp authdiff.config.example.json config.json

# 3) ازرع canary في الحقل الخاص بكل هوية
python3 authdiff.py seed --config config.json --authorized

# 4) شغّل الاختبار التفاضلي (بيطبع النتائج المثبتة بالـ canary بس)
python3 authdiff.py run  --config config.json --authorized

# بديل: لقّمه HAR لكل هوية بدل ما تكتب "observed" بإيدك
python3 authdiff.py run  --config config.json --har alice=alice.har --har bob=bob.har --authorized

# 5) (اختياري) أكّد تجاوز مورد أحادي الاستخدام بالـ single-packet racer
python3 authdiff.py race --config config.json --authorized
```

### نقط مهمة
- الـ HMAC secret بيتحفظ في `./.authdiff_secret` عشان `seed` و`run` يشاركوه. خليه في نفس
  المجلد بين الأوامر (لو اختلف السر، الـ canary مش هيتحقق).
- الـ single-packet racer محتاج **HTTPS (h2 over TLS)**؛ الـ `run` العادي بيشتغل على
  HTTP/1.1 أو h2.
- محتاج **هويتين على الأقل** — الاختبار تفاضلي بطبيعته.

### خارطة الطريق
- أوامر `bfla` / `bopla` كاملة (أوراكل I2 / I3)
- تكامل مع أداة مراقبة السطح المستمرة (DeltaHunter)
- تصدير تقرير حامل للإثبات (Markdown / جاهز لـ HackerOne)

### إخلاء مسؤولية
المشروع ده **للاختبار الأمني المصرّح به والتعليم فقط**. إنت وحدك المسؤول عن استخدامه. متختبرش
أنظمة مش ملكك أو مالكش إذن كتابي صريح باختبارها. بدون أي ضمان. اكتشاف وPoC بس — مفيش أي
استغلال مُسلّح.

### الرخصة
MIT — شوف ملف [LICENSE](LICENSE).
