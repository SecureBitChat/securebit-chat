# Changelog

## v6.7.3 — Faster loading, and pages search engines can actually read

Loading got a lot lighter. The bundles used to carry all thirteen translations at once,
and a page fetched them a third time as raw source; now each page loads only its own
language. On top of that the JavaScript is minified, the eight stylesheets are served as
one file, the QR scanner is fetched only once the app is up rather than on every visit,
and the fonts and icons ship at the size they are actually used at — Inter was shipping
the same file five times over, and Font Awesome was sending 2468 icons for the 82 this
app draws.

The page went from 1.85 MB across 43 requests to under 700 KB across 33. On a mobile
connection it now starts drawing in 1.6 s instead of 6.3 s and is usable in 4.5 s
instead of 11 s.

Pages also arrive with their text already in the HTML. Everything used to be drawn by
JavaScript into an empty div, so a search engine saw correct metadata wrapped around
nothing — which is why twelve of the thirteen language pages had never been shown to
anyone. Each page now carries its own headline, features and roadmap in the markup,
visible to crawlers and to anyone without JavaScript, and replaced by the app the moment
it loads. The documentation is published as real pages under `/docs/` with a new FAQ,
and an address that does not exist returns a proper 404 instead of the app.

One fix worth calling out: the localized pages were being served with a year-long cache
header meant for static assets. Anyone who opened `/de/` or `/ru/` was pinned to that
build and could not receive an update. The header is corrected, and the service worker
now refreshes what it cached, so affected browsers recover on their next visit.

Three unused components were removed along the way, and the placeholder testimonials
that were never wired into the site are gone from the repository.

## v6.7.2 — Desktop 1.0.1

Download links point at desktop 1.0.1, which is the first build that works on
Linux at all.

1.0.0 could not open a channel there. WebKitGTK is built with WebRTC compiled
out — its own configuration ties `ENABLE_WEB_RTC` to `ENABLE_EXPERIMENTAL_FEATURES`,
which release builds turn off — so `RTCPeerConnection` was not a variable that
existed, on any distribution, in any package format. The desktop client now
carries its own WebRTC in Rust and presents the browser's API shape to the page,
so the connection code stays the same one this repository shares with it.

Calls are not available on the Linux desktop yet and it says so; they are
unaffected on macOS, Windows and here in the browser.

## v6.7.1 — Download links for desktop 1.0.0

The desktop client reached 1.0.0, and the buttons on this site now point at it.

The version was written in two places: the compact table in `src/app.jsx` and the
grid in `src/components/ui/DownloadApps.jsx`. Only one of them was bumped, so
half the buttons pointed at a tag whose filenames no longer exist — the link
still looked valid and downloaded nothing. That is the exact failure
`tests/desktop-download-links.test.mjs` was written for after it happened twice
before, and it caught this one: every generated URL is fetched during the test,
so a link that leads nowhere fails the build rather than the visitor.

Worth saying plainly, because it is the part that is easy to get wrong: the page
loads the bundles in `dist/`, not the `.jsx` sources. Editing a source and
deploying without rebuilding changes nothing that anyone sees.

The translation scan also learns that these dictionaries feed two clients. The
desktop client lives in a separate repository, so its `desktop.*` keys can never
turn up in a scan of this `src/` — they were being reported as dead strings to
delete. The exemption is narrow on purpose: any other unused key still fails.

## v6.7.0 — Group calls

Groups can call now. Press the handset in a group's header for voice, the camera
for video, and everyone in the group gets a ring. Whoever joins appears as a tile
of their own; tap somebody to give them the whole screen and drop the rest into a
strip along the bottom. Mute, camera, front/back, and a green ring around whoever
is talking.

**There is no conference server, and there was never going to be one.** The usual
way to do this is to send everyone's audio to a machine in the middle that mixes
it and sends one stream back. It is cheaper, it scales further, and it means a
computer you do not own is holding the room. A group call here is instead a
separate encrypted call to each other member, over the connection you already
built with them and already verified in person by reading the safety code aloud.
Four people means three calls out of your browser. That is the honest cost of the
room only existing on the devices that are in it.

**Nobody's phone rings for a call they were not invited to.** Who opened a call
and who is in it travels as a message signed with the sender's group key — the
same signature the group's text messages carry. Members who cannot reach each
other directly pass those messages along for one another, which is how a group
works here, and a member passing one along can drop it but cannot write it. So
nobody can add you to a call you never joined, take you out of one you are in, or
hang up on the group.

**Your microphone opens once, for the whole call, and only after you agree.** One
capture is shared across every connection rather than one per person, which is
also what stops the browser asking a group of six for permission six times. It
stops the moment you leave — including if you close the group, or the tab.

**A member with no direct link is in the call, not missing from it.** Groups start
as a star, with only the person who created it connected to everyone, and build
the remaining connections quietly afterwards. Someone still being connected shows
as connecting rather than being left out of the list, and joins when their link
comes up.

**Also in this release:** the safety code now asks for a number instead of text,
so phones open a keypad rather than a full keyboard for an answer that is always
seven digits. And starting a new chat from inside a group works — it used to
create the chat behind the group and leave it invisible, which meant that while
you had a group open you could not connect to anybody new, or add anybody to the
group.

## v6.5.0 — It asks, in your language

If your browser reads Arabic and you land on the English page, a small bar now
appears in the corner: "هذه الصفحة متوفرة أيضًا بالعربية" - with a link. One
click and you are on `/ar/`. Dismiss it and it never comes back.

**What it deliberately does not do is move you.** The obvious version of this
feature reads the browser's language on load and redirects. It looks right from
your own machine and quietly ruins the site everywhere else. Search engines
crawl from one place with one language set, so a redirect answers every one of
the thirteen locale addresses with the same page - and the twelve translations
stop existing as far as the index is concerned, however carefully they are
linked. Shared links break the same way: a link posted in a German group chat
has to open in German for everyone who follows it, including the person whose
laptop is set to English.

So the address still decides the language, always. The bar is an offer sitting
next to it: written in the language it is offering, laid out in that language's
direction, and gone for good once you say no.

## v6.4.0 — Now it reads right to left

Arabic, Hebrew, Persian and Urdu, at `/ar/`, `/he/`, `/fa/` and `/ur/`.
Thirteen languages in all.

**Translating the words was the smaller half.** In these languages the whole
page runs the other way: the avatar sits to the left of the name instead of the
right, the drawer slides in from the right edge, the chevron that means "next"
points the other way. A messenger that only swapped its words would be a
left-to-right app wearing Arabic - readable, and wrong in a way that is tiring
rather than obviously broken.

**So the layout no longer has a left and a right.** It has a start and an end,
and which side those land on is decided by the language. That is one line in the
page - `dir="rtl"` - and a few hundred small changes underneath it, every margin
and every corner rewritten to say "the side the text starts from" instead of
"the left". The English page is pixel-for-pixel what it was.

**The drawer follows your thumb the way it should.** Swiping it open is a
gesture, not a button, and a gesture that ignores direction pulls the wrong way
under the finger - which feels less like a bug and more like the phone
misunderstanding you. It now enters from whichever edge the language starts at
and tracks the same way in both.

**Keys and codes stay left-to-right, deliberately.** This is the part that would
have been dangerous to miss. A browser rewrites the order of a mixed run of text
inside a right-to-left paragraph, and a safety code or an invitation is exactly
such a run: `a1b2:c3d4` can come out as `c3d4:a1b2`. Every character is still
there, so nothing looks wrong - and someone comparing that code against their
peer's screen would be comparing the wrong thing and confirming a channel they
never actually verified. The safety code, the invitation, the answer and the
server list are all pinned to one direction now.

**Fonts come from your device, as before.** Inter carries no Arabic or Hebrew,
and a webfont worth reading in those scripts is bigger than the rest of the app.
Every platform that reads them already ships a good one, so the page asks for
that instead - and no font request leaves your browser, which is why Inter was
self-hosted in the first place.

**The language menu scrolls.** Thirteen entries is taller than a phone held
sideways, and the last few were off the bottom edge.

**The app was never installable in any language but English.** The Service Worker
was registered as `./sw.js`, which from `/de/` asks for `/de/sw.js` and gets a 404 -
so twelve of the thirteen pages had no worker at all: no offline shell, no update
prompt, nothing to install. It was invisible from the English page, the only one
where a relative path happens to land in the right place. It is registered from the
site root now, with the whole site as its scope, so an app installed from `/ar/`
stays covered when it navigates anywhere else.

**A build could ship a page in a language the app had never heard of.** The bundler
ran before the dictionaries were generated, so a newly added language reached the
served page - correct title, correct direction - wrapped around an app still working
from the previous build's list. The steps are in dependency order now, and a test
reads the shipped bundle back to confirm every language is actually in it.

## v6.3.0 — Now it speaks your language

The site is now available in German, French, Spanish, Ukrainian, Russian,
Chinese, Korean and Hindi, alongside English.

**The language picker is a dropdown of short codes.** Nine full native names do
not fit a phone header, so the control shows the current code and opens a list.
The entries are still ordinary links, and they stay in the document whether the
menu is open or shut.

**Each language has its own address.** German lives at `/de/`, Spanish at
`/es/`, and so on. That sounds like a detail, but it is the whole point: a page
that only changes language when you click a button has one address for every
language, so a search engine can only ever find one of them, and a link you send
someone opens in whichever language *they* happened to pick last. Now the link
you copy is the page you were reading, in the language you were reading it.

**The language you asked for wins.** Open `/uk/` and you get Ukrainian, even if
you chose English here yesterday. Your choice is remembered for when you arrive
somewhere that doesn't say — but it never overrules an address you typed or a
link a friend sent you.

**Nothing redirects you.** If your browser says it prefers Spanish, the site
does not throw you at the Spanish page — it offers. Automatic redirects are how
sites end up invisible to search engines outside one country, and how someone who
deliberately opened the English page keeps getting bounced away from it.

**The translations were written, not machine-generated.** The landing page, the
key exchange, the safety-code check, the install prompt and every section below
them read as they should in each language - including all thirteen roadmap
entries and the ninety-four bullets under them. That is 623 strings per
language - 5,607 translations in all.

**The update notice showed up on every page load.** "Back online" describes a
transition - being offline, then not - and on a fresh load no such transition had
happened, so the pill was announcing something that never occurred. It now
appears only when there is actually a problem. It became obvious once switching
language started reloading the page.

**Build timestamps follow your language.** The update dialog formatted its dates
as 08/28/2026 for everyone; a German reader now sees a German date.

**Long dashes are now plain hyphens.** Titles and descriptions used a typographic
em dash; they now read "SecureBit.chat - Private, Encrypted Messenger" in every
language.

**Partner logos were pointing at the wrong place.** Their paths were written
relative to the page, so on `/de/` the browser looked for them under `/de/logo/`
and found nothing. There is now a test that fails on any relative asset path
anywhere in the source, because this is a bug you cannot see while you only ever
open the English page.

**A search engine can finally see the site.** There was no `robots.txt` and no
`sitemap.xml` at all — now both exist, and the sitemap lists every language with
the right cross-references between them.

**The people in the animation have local names.** The loop on the front page
shows two contacts joining a mesh. They were mara and tobi everywhere; now they
are lena and jonas in German, lucía and mateo in Spanish, 小红 and 小明 in
Chinese. The point of that animation is "someone you know just joined", and a
foreign-looking name quietly undercuts it.

**The chat is translated too.** Not just the landing page: the composer, message
states, disappearing and view-once messages, voice notes, file transfers, calls,
group chats and their safety-code ceremony, the connection details panel, and
every error you can hit along the way.

## v6.2.0 — The interface answers you now

Most of this release you will feel rather than see.

**The menu on your phone is something you can drag.** Before, it was either
there or it wasn't — it appeared, and tapping outside made it vanish. Now you
can pull it in and push it away with your finger, and it stays under your thumb
the whole way. Flick it and it goes; catch it while it's still moving and it
follows you back. Push it past the edge and it resists instead of stopping dead,
so you can feel that there's nothing more that way.

**Buttons react the moment you press them, not when you let go.** On a phone
that was the difference between an app that felt asleep and one that answers.
Along with it went the small delay every mobile browser adds to a tap while it
waits to see whether you meant to zoom — nothing here zooms, so the wait bought
nothing.

**If you've asked your phone or computer for less motion, the app now listens.**
Looping decoration stops, things fade into place instead of sliding, and the chat
jumps to the newest message instead of scrolling to it. Recording indicators and
anything else that tells you what's happening stay — the point is to stop the
movement, not the information. The same goes for the system settings for reduced
transparency and higher contrast, which the app previously ignored: frosted
panels become solid, and edges get drawn properly.

### Also in this release

- Headings are set more tightly and small print more openly, the way type is
  meant to change shape as it changes size. Text over blurred panels is a little
  heavier so it stays readable against whatever is moving behind it.
- The bar at the top of the page is a thicker piece of glass, and it now
  materialises as you scroll rather than simply fading in.
- Controls no longer stay stuck in a highlighted state after you tap them on a
  touchscreen.
- Keyboard focus is visible everywhere.
- The desktop download buttons now offer 0.5.0, the release that adds group
  chats. Linux gained `.deb` and `.rpm` packages alongside the AppImage the
  button hands you.

## v6.1.1 — Group chats now connect everyone to everyone

Group chats used to run through whoever created them. That person held a
connection to every member, and nobody else was connected to anybody — so when
you wrote to someone in the group, your message went to the creator first and
they passed it along. It worked, but it meant one person could see when everyone
else was talking, and if they closed the app the group went quiet.

Now every pair in a group connects directly, by themselves. It happens on its own
a few seconds after everyone has confirmed the group code, and you can watch it
in the header: it goes from "2 of 3 connected" to "3 members · P2P mesh". If two
of you already had a private chat open with each other, the group just uses that
instead of building a second connection.

The practical difference: whoever created the group is now an ordinary member.
They can close the app and everyone else keeps talking.

### Also in this release

- When somebody can't be reached directly, their messages still travel through
  another member — and a message that arrived that way is now marked "relayed",
  so you can see when it happens.
- When somebody goes offline, the group says so once and by name, instead of
  repeating a notice under every message you send until they come back.
- A connection that drops and can't be repaired is now rebuilt through someone
  else, rather than staying dead for the rest of the conversation.
- The warning about relayed messages no longer appears when nothing is being
  relayed — it used to count people who were simply offline.
- Group connections no longer interfere with the display of whichever chat you
  happen to have open.

### Security

- **Fixed: any member of a group could add anyone else to it.** Only the person
  who created the group was ever meant to be able to invite, but the check for
  that was missing — a reply to an invitation was accepted from anyone who knew
  the group's id, whether or not they had been invited. You would have noticed,
  because a new member appears in the list and everyone's group code changes, but
  noticing should not have been the only thing standing in the way.
- The details two members exchange to find each other travel through a third
  member, so they are now signed. That member can refuse to pass them along, but
  they cannot swap them for their own and end up sitting in the middle of the
  connection.
- Nobody is asked to compare a code for each of these new connections. For a
  group of eight that would be twenty-eight codes, which is not a check anyone
  actually performs — the group code everyone already compared covers them.

## v6.0.8 — An offline group member reads as offline

### Fixed

- **A regression from 6.0.7: closing a departed peer's chat could strand a group
  member.** That release removed the 1:1 chat when a peer disconnected, but a
  group is built out of those very sessions — one of them is the group's only
  route to that member. Tearing it out made them permanently unreachable and left
  nothing to re-bind when they came back. A session carrying a group member is
  now kept, on both the peer-departure and recovery-exhausted paths.
- **An offline member is now unmistakable in the member strip** — struck through,
  dimmed, marked `offline`, with a tooltip saying they will not receive messages
  and that removing them re-keys the group. They stay listed, because a dropped
  connection is not a departure: membership is a signed, epoch-ordered fact, and
  re-keying the group every time somebody's network hiccups would make everyone
  re-compare a code for nothing. Removing a member is still available to the
  admin, on the member chip, and that one does open a new epoch.
- **A relayed message is no longer counted as delivered when the recipient is
  offline.** A relay hop is unacknowledged: the frame is handed to a member who
  may or may not reach the target, and nothing comes back either way. For someone
  we have never held a link to that is the normal path. For someone whose link we
  lost it is a guess, and counting it told the sender their message had arrived
  when there was no reason to believe it. The frame is still relayed — the target
  may be reachable elsewhere in the mesh — it just no longer inflates the count.

## v6.0.7 — Dead chats clear themselves; the group code button is gone

### Removed

- **The Code button in the group header.** It opened a dialog that had nothing to
  say once the group was ready — the code arrives on its own when there is
  something to compare, and the header already carries it beside the member
  count. A control that reports "Working…" forever is worse than no control.

### Fixed

- **A chat the peer walked out of no longer lingers in the rail.** `peer_disconnected`
  comes only from an explicit peer_disconnect frame, never from a transport drop
  an ICE restart might repair, so it is terminal: there is nothing to reconnect
  to, and the chat is now removed rather than sitting there advertising a closing
  notice as its last message. A plain `disconnected` is deliberately left alone —
  that one is recoverable and keeps its history.
- **System notices no longer hijack the chat preview.** The rail showed whatever
  message came last, so "Enhanced secure connection closed. Check connection
  status." replaced the last thing the peer actually said — while the status line
  right next to it was already saying the same thing, better. The preview now
  skips system messages and falls back to the connection status when a chat has
  nothing else.

## v6.0.6 — Invite into a running group; departed members actually disappear

### Added

- **The admin can invite more people into a group that is already open.** An Add
  control in the group header offers the verified 1:1 chats that are not already
  members. The group keeps working while the invitation is outstanding — nothing
  about the membership changes until the new members publish their identity keys
  and a roster for the next epoch goes out. Then everyone, old and new, runs a
  fresh commit/reveal round and compares a new code. That is not ceremony for its
  own sake: the safety code covers the member set, so a set that has changed has
  a different code and the old one no longer describes who is in the room.
- If nobody accepts, the round is abandoned and the group is left exactly as it
  was — which is why the epoch is not touched until the roster is actually sent.
  A partial answer still publishes, with whoever joined.

### Fixed

- **A member who left stayed on the admin's list.** The admin removed them from
  its own member map and then never told the interface, so someone who had
  visibly left was still shown as present until some later event happened to
  refresh the view. A group should not be vague about who is in it.
- **A fast invitation could abort a round that had already succeeded.** Whether
  anything had been sent was judged by what was left in the pending-hello queue,
  but on a fast link the invitee's hello comes back — and the whole round
  completes — inside the very call that sent the invitation, so the queue was
  legitimately empty by then. It is now judged by the send results.

## v6.0.5 — Group formation stops hitting the rate limiter

`frame_rejected` on one side, `ceremony_timed_out` on the other: two symptoms,
one cause.

### Fixed

- **Forming a group exceeded the transport's burst limit and lost frames.** The
  manager allows ten sends per second, but a group frame spends *two* of those
  slots — `sendMessage` checks the shared limiter and then hands off to
  `sendSecureMessage`, which checks the same counter again. Formation sends six
  frames back to back on one session (invite, two member keys, roster, commit,
  reveal), asking for twelve slots out of ten. The overflow was rejected as a
  plain `Error` carrying no code, so it reached the user as the meaningless
  `frame_rejected`, while the peer that never received the dropped frame simply
  waited until the ceremony timed out.

  Group frames now go through a per-session queue that serialises and paces them
  at five a second. Formation takes about a second and a half. The limiter itself
  is untouched: widening a control that exists for the 1:1 chat, to suit a caller
  that can perfectly well wait, would have been the wrong trade.

  Ordering is enforced by the same queue. The protocol depends on it — a
  commitment has to reach a peer before the reveal that opens it — and firing
  several sends concurrently at one channel left that to the manager's internal
  mutex.
- **A rate-limited frame is retried instead of dropped.** Losing one frame of a
  handshake strands every member of the group, so it is worth waiting for.
  Failures that will not improve on their own — a closed channel, a refused
  verification gate — are still reported immediately rather than retried.
- **An error with no code of its own keeps its message.** Collapsing every such
  failure to a bare `frame_rejected` threw away the only clue about what actually
  happened, which is what made this bug take three rounds to find.

### Added

- `group-sender.test.mjs` reproduces the limiter's real accounting — ten slots a
  second, two per frame — and asserts that all six formation frames land, in
  order, spaced. It also asserts the failure directly: with pacing disabled, the
  same run is rejected, and the rejection carries no `code`, which is exactly how
  it reached the user.

## v6.0.4 — The group code appears, and a failed group says so

Three bugs, one visible symptom: the safety code never showed and the confirm
button stayed disabled. They are listed worst-first.

### Fixed

- **A failed ceremony could be confirmed into a working group.** `CONFIRM_SAS`
  required only that a code existed. A ceremony that reached the code step and
  *then* failed — a commitment that did not match its reveal, a member that
  vanished — kept that code, so confirming promoted a group whose verification had
  demonstrably gone wrong straight to ready. Confirmation now also requires the
  group to still be waiting on that code, which is the group's version of the 1:1
  rule that verified state comes only from the user acting on something currently
  true.
- **A group name in a non-Latin script broke formation silently.** The create
  dialog capped input at 64 *characters* while the protocol enforces 64 *bytes*,
  so a perfectly ordinary 36-character Cyrillic name is 68 bytes: accepted by the
  dialog, then rejected inside the admin's roster signing. Formation died with
  nothing on screen and the invitee waited for a member list that was never sent.
  The budget is now 128 bytes and every place that trims a name — the dialog, the
  rename action — counts bytes.
- **The safety-code dialog reported "Exchanging nonces…" for a group that had
  already failed.** It only distinguished one phase from everything else, so a
  dead group was indistinguishable from a working one; the disabled confirm button
  was the only hint. It now names the real state and, on failure, says what went
  wrong in words worth acting on and offers Close instead of a confirm button that
  cannot do anything.

### Added

- **Coverage for the seam between the protocol and the screen.** Every previous
  group test drove `GroupSession` and read its fields, leaving the path the UI
  renders from — emitted event, dispatched action, reducer state — untested. That
  is exactly where these bugs lived. `group-app-integration.test.mjs` mirrors the
  app's emitter and asserts the code reaches the *store* on both sides, including
  with a Cyrillic group name, and that a failed group is never confirmable.

## v6.0.3 — New connection animation, and a re-ordered roadmap

### Changed

- **The landing page's left panel has a new animation.** The old one was a single
  static wire between two avatars with dots sliding along it. The replacement is
  a 14-second loop that tells the whole story: a direct line to one peer, then
  two more joining it — which is what v6.0 actually shipped. It is drawn as one
  SVG and animated entirely in CSS, with packets moving along `offset-path` built
  from the same geometry the lines are drawn from, so a packet can never drift
  off its wire. No requestAnimationFrame loop, so a landing page left open costs
  nothing. Under `prefers-reduced-motion` it holds on the finished state rather
  than disappearing, so the picture still reads as a mesh of three.
- **Mobile Edition moved up to v6.5 and is marked in development**, swapping with
  Quantum-Resistant Edition, which moves to v7.0.

## v6.0.2 — Groups form reliably, and leaving one frees its members

### Fixed

- **A group no longer sticks at "Exchanging nonces".** Held commitments were
  replayed *before* our own commitment went out, and replaying them could
  complete the commit round on the spot — which revealed our nonce and put a
  reveal on the wire ahead of the commitment it belongs to. The peer then held a
  reveal it could not check yet and waited for a commitment that was already
  behind it in the queue, so both sides sat there: one at "exchanging nonces",
  the other still collecting commitments. Every member now broadcasts its own
  commitment first and replays held frames afterwards, so a reveal can never
  outrun it. Asserted directly by a wire-order test on the smallest case, a group
  of two, which is where it was reported.
- **Leaving a group actually ends it for the other side.** `leave()` was started
  but not awaited before teardown, and teardown clears the member map that
  `leave()` walks to find recipients. Worse, a member who did hear it kept the
  group anyway: only the admin acted on a departure. When the admin leaves there
  is nobody left who can sign a roster, so there is no next epoch and no code to
  compare again — the group is over, and it is now removed instead of lingering
  as a chat that can never send.
- **Removing the second-to-last member no longer breaks the group.** It tried to
  publish a roster for a group of one, which threw out of the member-list
  validator part-way through the removal and left the group in a failed state.
  The floor is now checked first and reported.
- **An invitation that cannot be sent says so immediately.** Send failures were
  swallowed, so inviting someone over a dead link produced forty-five seconds of
  silence and then a generic timeout — indistinguishable from an invitee who had
  not answered yet. A send that fails for every invitee now fails at once, naming
  the cause; if only some links are down, the unreachable invitees are dropped
  from the round instead of stalling the roster forever.

### Changed

- **The roadmap reflects what shipped.** Group Communications and Mobile Edition
  swap places: groups are v6.0 and current, native mobile apps move to v7.0, and
  Secure Voice & Calls is marked released rather than current. The group entry
  also lists what was actually built instead of what was guessed at — there is no
  Double Ratchet "for groups" and no ephemeral-group mode; there are pairwise
  ratchets, a commit-then-reveal safety code, and signed membership.

## v6.0.1 — The group code now actually appears

### Fixed

- **The safety code opens on its own again.** Whether to show it was decided by
  comparing the finishing group against a ref that React assigns during render.
  The commit/reveal round completes in a run of microtasks that outpaces the
  re-render, so that ref was still null and the modal never opened — leaving a new
  group sitting silently at "Compare the group code" with the digits reachable
  only through a button. The group that produced a code is now brought forward
  directly, which both shows the modal and guarantees it is pointed at the right
  group when more than one is forming.

## v6.0.0 — Group chats

Up to eight people in one peer-to-peer conversation, with no server and no shared
group key. A group is an orchestration layer over the 1:1 sessions that already
exist: every group message travels over a pairwise Double Ratchet that was already
verified, so the group inherits the forward secrecy and the transport of the chats
it is built from rather than introducing a second, weaker path.

### Added

- **Group chats, up to 8 members.** Create one from the 1:1 chats you have already
  verified. Unverified chats are not offered: a group built on a session whose
  safety code was never compared would inherit that open question and hide it
  behind a group code that looks like it settled the matter.
- **A group safety code, compared once by everybody.** Seven digits, the same
  length as the pairwise code, derived from every member's group identity key and
  a secret nonce each of them contributes. Nothing is sent until the humans
  confirm it.
- **Commit-then-reveal, which is what makes seven digits enough.** The obvious
  construction — hash the member keys and show the digits — is not safe at a
  length people will read aloud. A member who introduces two others controls what
  each of them sees and can generate candidate keys until the two truncated hashes
  collide; that is a birthday search of roughly 10^(d/2), and seven digits falls
  in a few thousand tries. Signal answers this by making the safety number sixty
  digits. Here every member instead publishes a hash of a secret nonce first, and
  no nonce is revealed until every commitment has arrived — so an attacker must
  fix both of their commitments before seeing a single honest nonce and is left
  guessing once, at 10⁻⁷. The gate has one implementation and refuses to reveal
  early, including on a timeout.
- **Signed membership, ordered by epochs.** Every change of membership is signed
  by the group's admin over the resulting member set, and only a strictly greater
  epoch is accepted — which refuses both a replay and a rollback to a membership
  that used to be valid. Removing a member opens a new epoch, so the group re-keys
  and everyone compares a fresh code.
- **Signed messages, so a split transcript is provable.** Messages fan out over
  N-1 independent ratchets, so each recipient only learns that the sender's
  session sent it. A signature over (group, epoch, sequence, body hash) means a
  member who tells two halves of the group different things under one sequence
  number produces two valid signatures — non-repudiable evidence rather than
  suspicion. The offending message is discarded and named in the transcript.
- **Delivery over a direct link where one exists, relayed where it does not.** A
  full mesh needs N(N-1)/2 pairwise connections and at creation only the admin
  holds a link to everyone. Rather than block the group, a frame for an
  unreachable member is handed to a member who can reach you both. Because every
  frame is signed, a relaying member can drop or read a frame — reading is what
  membership already entitles them to — but cannot forge, alter or reattribute
  one. Relaying is single-hop by construction, and the member strip shows who is
  direct and who is not.
- **Partial delivery is reported.** With no server there is nobody to hold a
  message for an absent member, so a send that reached only some of the group says
  so in the transcript instead of looking like it succeeded.
- **A warning before you create a group without relay-only.** In a mesh every
  member connects to you directly and learns your address — including members
  somebody else invited. That is a real step down from a 1:1 chat and it is said
  before you commit, not after.

### Notes

- The group layer required **no changes to the WebRTC manager**. Group frames ride
  `sendMessage`, the same authenticated and ratcheted path chat text takes, and
  are lifted out before they can reach a 1:1 transcript.
- Frames travel base64-wrapped. The chat path sanitises what it sends — DOMPurify
  escapes `<`, `>` and `&`, control characters are stripped, blank runs collapse,
  and the result is cut to 2000 characters — all of which is correct for chat text
  and fatal for a signed frame, whose body would no longer match the hash its
  signature covers. Base64 has no character that path rewrites. A group message is
  bounded at 1024 bytes so a frame always fits underneath the same ceiling.
- There is no message history for a member who joins: a group starts empty, and
  without a server there is nothing to backfill it from.
- Group calls are not in this release.

## v5.9.2 — Responsive layout fixed for phones

The chat was not laying out correctly on phones, iPhone worst of all: the header
would not stay at the top, and the layout shifted around as you scrolled or opened
the keyboard. The responsive behaviour is fixed.

### Fixed

- **The header stops scrolling away on iPhone.** The shell and the app column both
  carry `.minimal-bg`, which sets `min-height: 100vh` — and `min-height` always
  beats `height`. On iOS `100vh` is the URL-bar-retracted *large* viewport, so with
  the bar showing the shell was held some 60–100px taller than the area you can
  actually see. That surplus is what made the document scrollable, and a document
  that scrolls is how the header rode off the top. Removing the floor is also what
  makes everything below work at all: measured with `--sb-vh` forced to 700px, the
  shell stayed 844px before the fix and follows to 700px after.
- **The online/offline toast no longer covers the peer name.** It is `fixed top-4`,
  which inside the chat landed on the 64px header; it now sits below it.
- **The chat shell is sized from the visual viewport instead of guessing.** Its
  height follows `visualViewport`, with `100dvh` as the fallback — which is
  already correct on Android, where `interactive-widget=resizes-content` makes the
  layout viewport shrink for the keyboard. WebKit has not implemented
  `interactive-widget` at all, which is why the JS fallback exists.
- **The layout no longer resizes while you scroll.** Height was recomputed on
  every `visualViewport` scroll event, which on iOS fires while the URL bar
  collapses and during rubber-banding, so the whole chat twitched under the
  finger. It now tracks resize only.
- **Safe-area padding actually applies, and gets out of the way.** The composer
  already padded for the home indicator with `env(safe-area-inset-bottom)`, but
  the viewport meta lacked `viewport-fit=cover`, so the value was always 0 on
  notched iPhones. It now also collapses while the keyboard is up, where it would
  otherwise be dead space between the composer and the keyboard.
- **The message list can shrink.** It is `flex: 1` in a column, which defaults to
  `min-height: auto`: it refused to shrink below its content and pushed the
  composer off the bottom of the screen in a long conversation. It is also the
  only scroller now, and no longer chains its scroll to the document.
- **The chat header stays at the top**, via `position: sticky` on the header and
  nothing else. If an ancestor scrolls — which is what iOS does to lift a focused
  input above the keyboard — the header holds against the top instead of riding
  away with the page.
- Nested containers no longer each claim a full viewport height, which counted
  the header twice.

### Added

- `?preview=chat` renders the chat layout with canned content and no connection,
  so it can be looked at without standing up a handshake first. Presentational
  only: no peer manager, no keys, no network, and the send handlers are no-ops.

The shell is sized, not pinned. An intermediate version of this fix used
`position: fixed` with a JS-chased viewport offset and a body scroll lock; that
makes the layout feel nailed down rather than laid out, and a fixed box is laid
out against the layout viewport — the one iOS never shrinks for the keyboard — so
it has to be chased forever. Driving height and leaving positioning alone is what
the established iOS chat implementations do.

## v5.9.1 — Scanning a one-frame invitation

### Fixed

- The QR scanner waited for four frames when shown a single one. Its chunk
  assembler was written for SB1, which the generator always cuts into exactly
  four frames, and its fallback branch claimed any non-JSON string longer than
  100 characters — which a 151-character SBQ2 invitation is. A complete
  invitation was filed as chunk 1 of 4 and the scan never finished. SBQ2 payloads
  are now recognised as complete before any assembly runs, in both the text and
  raw-byte forms.


## v5.9.0 — The invitation is now one small QR code

The connection descriptor moves to SBQ2 and the key material moves onto the
DataChannel. Measured on the live site: the invitation payload went from **2274
characters across 4 animated QR frames to 151 characters in a single frame**.

### Changed

- **Invitations use the SBQ2 format.** The out-of-band code now carries only what
  brings up DTLS — ICE credentials, the certificate fingerprint, candidates, an
  expiry — plus a 16-byte commitment to the key material.

- **Key material is exchanged in band.** The ECDH and ECDSA public keys travel as
  the first frame on the DataChannel, and are checked against the commitment from
  the invitation *before* they are parsed or imported. A mismatch closes the
  connection; it is not a warning.

- **The SAS is computed over a transcript** covering both descriptors verbatim and
  both key blobs, with length prefixes. Anything an attacker can alter anywhere in
  the handshake, in either direction, changes the digits the two people compare.

- **The HKDF salt is derived from that transcript instead of transmitted**, so
  every session key is bound to both DTLS fingerprints and every candidate, and
  neither side can steer it.

- **`authProof` is replaced by one signature over the transcript.** The old
  challenge/response echoed a nonce back across seven fields; the signature proves
  the same possession and binds the whole handshake at once.

- The Double Ratchet starts from the transcript-derived material. SBQ2 postdates
  the ratchet entirely, so support is implied by the format rather than advertised
  in it — which also removes the silent "peer is old, use static keys" fallback
  from this path.

### Rollback

`EnhancedSecureWebRTCManager.SBQ2_SEND_ENABLED = false` and redeploy puts every
new invitation back on SB1. Reception of both formats is unconditional and is not
governed by the flag, so a client built with it off still reads SBQ2 invitations.

### Compatibility

SB1 invitations are still read, and the animated multi-frame QR path stays for
them. A client older than 5.9.0 cannot read an SBQ2 invitation: from 5.9.0 on, an
unrecognised `SB<n>:` family reports "This invitation was created by a newer
version of SecureBit. Please update the app to connect." Versions 5.8.1 and
earlier predate that check and show a JSON parse error instead — the two ends must
both be on 5.9.0+.


## v5.8.1 — SBQ2 rebuilds SDP that Firefox accepts

Still nothing in the application calls the SBQ2 descriptor; this fixes defects in
it found by running live connections between real browsers.

### Fixed

- The rebuilt SDP omitted `raddr`/`rport` on srflx and relay candidates. RFC 8839
  §5.1 makes them mandatory for non-host candidates, and while Chrome tolerates
  the omission, **Firefox drops the candidate entirely**. Relay-only connections
  to Firefox failed 0/8 where the browser's own SDP succeeded 8/8. The STUN and
  TURN profiles hid it, because a host candidate pair connected instead.

- The template advertised `a=ice-options:trickle` and never closed the candidate
  set. A descriptor is a complete one-shot set with no channel to trickle over,
  so this promised candidates that could never arrive. Trickle is gone and
  `a=end-of-candidates` is emitted.

- The `m=` port and `c=` line were hard-coded to the `9` / `0.0.0.0` null default
  candidate, which is the trickle-ICE "nothing gathered yet" convention and false
  here. The most publicly reachable candidate is advertised instead — relay, then
  srflx, then host — falling back to the null form only when every candidate is
  mDNS, as Chrome does.

None of these change the descriptor: all three are serializer-side and cost zero
bytes. Sizes are unchanged at 98–149 bytes, QR version 6–8.

Verified across all 16 combinations of {Chrome, Firefox} x {Chrome, Firefox} and
four network profiles: **48/48 connections**, with every relay-only pair now
connecting over the relay.


## v5.8.0 — A connection descriptor that fits in a small QR code

No change to how messages are protected, and no change to how a connection is
established. This release adds the wire format for a much smaller invitation and
the code that reads and writes it; nothing in the application calls it yet.

### Added

- `src/network/descriptor/sbq2.js` — version 2 of the connection descriptor. The
  current `SB1:` payload runs 2000–2400 characters and needs QR version 38–40, at
  which point the app has to fall back to an animated multi-frame code. Measured
  on real Chrome and Firefox SDP across four network profiles, SBQ2 is **98–149
  bytes**, which is **QR version 6–8** — a single, instantly scannable image.

  The saving comes from sending only what is needed to bring up DTLS (ICE
  credentials, certificate fingerprint, candidates) and templating the SDP rather
  than shipping it verbatim. Key material is intended to move to the DataChannel,
  bound to the descriptor by a commitment; **that half is not implemented**, which
  is why the format is not yet in the connection path. See
  `doc/DESCRIPTOR-SBQ2.md` for the layout, the security argument and the migration
  gate.

  The decoder is written as a parser of hostile input: fixed offsets, explicit
  lengths, deny-by-default on every reserved value and on unknown extension types,
  trailing bytes rejected, and ICE credentials alphabet-checked so a CRLF cannot
  reach the SDP serializer. Compression is deliberately absent — on this payload
  DEFLATE adds bytes, and removing it removes the decompression-bomb surface too.

- `doc/DESCRIPTOR-SBQ2.md`, and `tests/descriptor-sbq2.test.mjs` covering
  round-trip against real Chrome and Firefox SDP, IPv6 and NAT64 addresses,
  ICE-TCP candidates, candidate-coverage pruning, the TLV extension area, clock
  skew, one-shot binding and the SAS transcript.

- `tests/fixtures/sdp-chrome.json` and `tests/fixtures/sdp-firefox.json` —
  SDP captured from real browsers rather than written by hand.


## v5.7.2 — Documentation, and a version that keeps itself honest

No changes to the protocol or to how messages are protected.

### Fixed

- The version shown in the application header was written as a literal and had
  fallen behind, displaying v5.6.0 while running 5.7.1. It now comes from
  `package.json`, so it cannot drift again, and a test fails the build if anyone
  reintroduces a hard-coded one. The same test checks that `meta.json`, the README
  badge and the changelog agree with each other before a release goes out.

### Changed

- Documentation reorganised. Everything technical now lives in `doc/`, with an
  index at `doc/README.md`. The root keeps only what belongs there by convention:
  `README.md`, `SECURITY.md`, `CHANGELOG.md` and `LICENSE`.
- `SECURITY.md` rewritten. It described a release line three major versions old
  and made claims the software does not make. It now states what is guaranteed,
  what is not, and how to report a problem.
- `SECURITY_DISCLAIMER.md` and `RESPONSIBLE_USE.md` merged into
  `doc/USE-POLICY.md`, which says plainly what the software cannot protect
  against instead of listing generic advice.
- `doc/CRYPTOGRAPHY.md` and `doc/ARCHITECTURE.md` rewritten to describe the
  current design, including the Double Ratchet, and to quote real values taken
  from the source rather than restated approximations.
- WebRTC call tuning notes moved to `doc/CALLS.md` and rewritten. The obsolete
  `docs/` directory, which held a working document full of stale line numbers,
  has been removed.
- `doc/CONTRIBUTING.md` now records what recent bugs taught us about writing
  tests that can actually fail.

## v5.7.1 — Forward secrecy now engages for both sides of a chat

The Double Ratchet introduced in 5.7.0 was only taking effect for the peer who
joined a conversation; the peer who created the invitation stayed on the
previous per-session key scheme. Both sides now negotiate and run it, so a
conversation is protected symmetrically end to end.

If you installed 5.7.0, updating is worthwhile — it is what makes per-message
forward secrecy apply to your whole conversation rather than one direction of it.

### Internal

- The ratchet's test suites now construct the peer's public key exactly as the
  handshake delivers it (exported and re-imported, non-extractable) rather than
  reusing a locally generated one. Locally generated public keys are always
  extractable in WebCrypto, so the earlier tests exercised a key shape the app
  never actually produces.

## v5.7.0 — Double Ratchet: forward secrecy for every message

Sessions previously derived one set of keys during the handshake and used them
for the whole conversation. This release adds the Double Ratchet (Signal's
design) on top of that, so protection no longer rests on a single set of keys
lasting the entire chat.

### Added

- **A separate key for every message.** Each message key is derived from a chain
  key through a one-way function and discarded immediately after use, so keys
  that exist now cannot be used to reconstruct earlier ones.
- **A Diffie–Hellman step on every change of direction.** Each reply introduces a
  fresh ECDH key pair and mixes a new shared secret into the root key. A session
  therefore re-keys itself continuously as the conversation goes back and forth.
- **Bounded handling of out-of-order messages.** Keys for messages that have not
  arrived yet are held so they can still be read, with firm limits on how many
  are kept (512 per chain, 1024 in total, expiring after five minutes) and a
  fixed ceiling on how far ahead a message number may jump.

The ratchet required no change to the handshake. Both peers already hold each
other's authenticated ECDH public key, and the safety code compared during
verification covers exactly those keys. The ratchet's root is derived from the
existing shared secret through its own branch of the key schedule, keeping it
separate from the session's other keys.

### Compatibility

Support is advertised in the invitation and the response and used only when both
sides have it. A peer on an earlier release negotiates it away and the session
runs on the previous scheme — with no server in the design there is no way to
update both ends at once, and connecting with the earlier protection is better
than not connecting. The security panel shows which of the two is actually in
use, rather than what the client is capable of.

One behaviour worth knowing: the peer who joins has no sending chain until the
inviting peer's first message arrives — that is inherent to the ratchet, since
both sides derive it from the same exchange. The app sends a presence update from
both sides as soon as verification completes, so those first frames use the
session keys and everything afterwards is ratcheted.

### Improved

- **Connection setup on restrictive networks.** Gathering network candidates only
  finishes once every configured STUN/TURN server has replied or timed out, which
  behind a VPN or a strict firewall may not happen at all. Setup now proceeds as
  soon as there are usable candidates and only keeps waiting while there are
  none, up to a longer ceiling. A network that genuinely yields nothing now
  explains what to try instead of failing without explanation.

## v5.6.2 — Restore connectivity after the 5.6.1 key-handling change

5.6.1 changed how the shared secret is handled in memory and missed a matching
adjustment to key generation, which prevented sessions from being established.
Anyone on 5.6.1 should update.

Key agreement is unchanged on the wire, so 5.6.0 sessions remain compatible.

### Internal

- Added an end-to-end test that drives the real key generator and derivation
  rather than constructing its own keys, which is what allowed the mismatch
  through.

## v5.6.1 — Hardening pass

A review of the client produced a set of improvements to how the session is
verified, how peer input is handled and what the app stores. Updating is
recommended.

### Improved — verification and peer input

- **The safety-code comparison is now the only route to a verified session.**
  Verification state is set in exactly one place, and the checks that guard it
  cannot be reached around.
- **Control messages are honoured only after verification.** Reconnection
  signalling, call setup, message deletion and delivery receipts all wait until
  both people have compared the safety code. The verification exchange itself
  continues to work beforehand, as it must.
- **A single path for incoming chat content.** An older, weaker inbound code path
  was retired so that everything shown in a conversation has been authenticated.

### Improved — accuracy of what the app reports

- **The security panel now measures what it displays.** Several checks previously
  reported a fixed result; they now exercise the subsystem they describe and can
  report a failure. As a result the score reflects the session more precisely,
  and may read lower than before on the same connection.
- **Forward-secrecy reporting matches reality.** In 5.6.1 the panel reported the
  session-level guarantee accurately rather than implying per-message protection;
  5.7.0 adds the per-message protection itself.
- **Clearer memory-handling semantics.** Operations that cannot clear a value in
  JavaScript — immutable strings, non-extractable keys — now say so instead of
  reporting success.

### Improved — what stays on the device

- **Invitation data is no longer kept in local storage.** An unused
  reference-based QR path wrote session invitation details to local storage
  without removing them; the path has been removed and existing entries are
  cleared on first launch after updating.
- **Ephemeral messages stay ephemeral.** View-once and disappearing messages no
  longer place their text in system notifications, where the operating system
  would retain it beyond the app's control. Ordinary messages are unchanged.

### Improved — hardening

- **Shared-secret handling in memory.** The value is derived into a buffer that is
  overwritten once it is no longer needed.
- **Scanned QR codes are decompressed with a size limit,** so a malformed or
  hostile code cannot exhaust memory.
- **Voice notes are validated before being accepted automatically.** Only genuine
  audio types within a size limit skip the consent prompt; anything else goes
  through the normal confirmation, which also bounds how much a peer can send
  unattended.
- **The master-password prompt now comes from the app's own interface** rather
  than a browser dialog.
- **Clearer handling of DTLS fingerprints,** with the local and remote values kept
  separate and reported accurately.

## v5.6.0 — Survive a dropped connection

A chat no longer dies when the network moves under it. Switching Wi-Fi → LTE,
a NAT rebind, a lift, a tunnel: the session now repairs its own network path and
the messages you typed meanwhile go out when it comes back.

This is done without adding any server. An ICE restart renegotiates *only* the
transport path; the DTLS handshake, the session keys and the SCTP association
carrying the data channel all sit above ICE and survive it. So the renegotiation
SDP travels over the existing end-to-end encrypted, SAS-verified channel — there
is still no signalling service anywhere in the design, and an attacker who cannot
already decrypt the session cannot inject a reconnection.

### Added

- **Automatic session recovery.** A broken path is repaired in place with an
  in-band ICE restart, retried with a 1/2/4/8/15/30 s backoff for up to two
  minutes. Keys, SAS verification and message history are all preserved — no
  re-handshake, no comparing codes again.
- **Liveness detection that understands sleeping devices.** A data channel keeps
  reporting `readyState: 'open'` long after the path underneath it has died — the
  classic Wi-Fi → LTE switch, where nothing closes and nothing errors, packets
  just stop. Silence alone is deliberately not treated as death, because a
  browser freezes a backgrounded tab outright and a healthy peer then answers
  nothing at all. What survives that freeze is ICE consent, which the browser
  runs in its network stack rather than on the page's thread — so a connected ICE
  state means a silent peer is asleep, not gone, and the session is left alone.
  Only when ICE itself is degraded does an unanswered probe end the session.
- **Recovery is given up promptly when it cannot possibly work.** Every route out
  of a broken path runs over the data channel, so if nothing at all has reached
  us since the drop, no further attempt can succeed. Likewise an ICE agent left
  bound to a network that is gone — every candidate times out, every restart ends
  with zero candidate pairs — cannot be repaired by restarting it. Both are now
  recognised in seconds instead of being retried for two minutes.
- **A session that cannot be recovered is closed, not left half-alive.** When the
  path is gone for good, the chat is ended and its data wiped — keys, queued
  messages and transcript together. There is deliberately no manual fallback: a
  conversation whose transport is gone should not leave its plaintext sitting in
  a tab, and starting a fresh one is a single, honest step.
- **Store-and-forward while reconnecting.** Messages typed during a repair are
  queued and delivered when the path returns, in order. A send that races a
  still-settling path is re-queued rather than marked failed.
- **The conversation stays on screen** during a repair, with a "Restoring
  connection…" state, instead of dropping you back to the connect screen.
- **A device with no network holds the session open.** Five minutes underground
  no longer costs a session: the give-up deadline does not run while this device
  has no connectivity, and recovery retries the moment the radio returns or the
  tab comes back to the foreground.
- `tests/session-recovery.test.mjs` covers the state machine, the backoff, the
  offline hold and the identity check below.

### Security

- **A reconnection cannot re-point a session at a different peer.** The DTLS
  fingerprint in an incoming restart offer or answer is checked against the
  fingerprint of the live, already-verified session *before* anything is applied
  to the peer connection. A mismatch aborts recovery. If there is no live
  fingerprint to compare against, the restart is refused rather than trusted.
- Only the side that created the original offer may drive a restart; the other
  side asks. With no signalling server there is no referee to resolve glare.
- Calls cannot be placed onto a path that is mid-repair, where the media
  renegotiation would race the ICE restart on the same connection.

### Fixed

- **Every inbound heartbeat threw a `TypeError`.** `handleHeartbeat()` was
  dispatched to but never defined, so peer liveness was never actually observed.
- **Heartbeats were sent every 5 minutes, not the intended interval** — the send
  was folded into the general maintenance cycle, far too coarse to notice a dead
  path. It now runs on its own timer, and answering one no longer requires the
  peer to have finished verifying: the two sides confirm a SAS code at different
  moments, and for that whole window one of them could not reply and was being
  declared dead on a healthy connection.
- **The answering side never started its watchdog.** `ondatachannel` can hand over
  a channel that is already open, so the `open` event had been dispatched before
  the handler was assigned and never fired — leaving that side with no heartbeat,
  no liveness watchdog and no file-transfer init. The peer whose network was fine
  kept showing "connected" indefinitely because nothing was running to notice.
- **A failed send no longer fails silently.** Sending on a channel that was not
  ready simply returned: the text stayed in the box, nothing was transmitted and
  nothing said why.
- **A transient `disconnected` no longer tears down the session.** ICE reports it
  routinely and the browser usually recovers unaided; it is now given a grace
  window before a restart is spent, and it never clears verification on its own.
- A reconnected session no longer re-announces "secure connection established" —
  it is the same session resuming, and no handshake took place.
- Liveness bookkeeping can no longer throw ahead of message routing, where the
  surrounding catch would have swallowed it and silently dropped every inbound
  message.

## v5.5.4 — Fix the desktop download buttons

### Fixed

- **The download buttons still led to a dead GitHub page.** 5.5.3 updated one of the two places these links live; the platforms menu on the connection screen has its own `DOWNLOADS` table, and it was missed. It still pointed at 0.1.0.
- The stale links used `/releases/latest/download/<file>`. GitHub resolves `latest` by redirecting to the newest tag, so once 0.3.0 shipped, a link written for 0.1.0 became `/releases/download/v0.3.0/SecureBit.Chat_0.1.0_x64-setup.exe` — a file that never existed under that tag. The button navigated to GitHub and downloaded nothing, which is why it looked like a working link that simply did nothing.

### Added

- `tests/desktop-download-links.test.mjs`, which fails the build if any source drifts: it requires every file to derive its URLs from one `DESKTOP_VERSION` constant, forbids `/releases/latest/download/` and hardcoded versions in filenames, and fetches each generated URL to prove the release asset is really there. Set `SKIP_NETWORK=1` to skip the fetches offline.

## v5.5.3 — Desktop downloads point at 0.3.0

### Fixed

- **The desktop download buttons still offered 0.1.0.** Windows, macOS and Linux now link to the current 0.3.0 release, which is the first with in-app updates, voice-note parity and the verification fixes.
- The release version was repeated across three URLs in two different forms (two resolving through `/releases/latest/`, one pinned to a tag), which is how they drifted out of date. It is now a single constant, and the tag is pinned deliberately: filenames carry the version, so a `latest` link breaks as soon as a newer release exists, whereas a pinned tag keeps serving a working installer.

## v5.5.2 — Fix security level in the header

### Fixed

- **Header showed "Secure undefined%".** Moving `getRealSecurityLevel()` onto the connection manager in v5.5.1 made it reachable for the first time, so the header started calling it instead of falling through to `calculateAndReportSecurityLevel()`. It returned only per-feature booleans — no `level`, no `score` — and the header renders those two fields directly. It now runs the same verified scoring as every other consumer and merges the feature flags on top, so all callers see one consistent number. A regression test pins the shape for every branch of the header's fallback chain.

## v5.5.1 — Security audit fixes

A security review of the transport and verification layers. Every item below is a
fix to how untrusted peer input is handled; no features changed.

### Security

- **SAS verification can no longer be bypassed.** `verification_both_confirmed` is an unauthenticated frame that arrives on a channel that is not yet trusted, but it was accepted as proof that both sides had compared their codes — so a peer who completed the signalling exchange could send it right after the data channel opened and drive the other side to a "verified" session while the user never looked at the code. It is now only an *acknowledgement*: it is refused unless this side has already confirmed locally, and `_setVerifiedStatus()` independently rejects any SAS-based transition without a local confirmation. Holding ECDH-derived keys was never sufficient proof of identity — a MITM has those too.
- **Unauthenticated frames can no longer be injected into the chat.** A bare `{type:"message"}` JSON frame, a raw non-JSON text frame, and a binary frame were each decoded and rendered in the chat, bypassing decryption, the HMAC check and the verification gate — the injected text was visually indistinguishable from a genuine message. Chat content now reaches the UI only through the authenticated `enhanced_message` path; everything else is dropped and logged.
- **A peer can no longer supply the verification code.** `sas_code` announcements were adopted verbatim when no local SAS had been derived yet, which would have shown the user a number chosen by the other end. The announcement may now only corroborate the locally derived code; a missing or mismatching code aborts the session.
- **File transfers are gated on verification in both directions.** File control frames (`file_transfer_start`, `file_chunk`, …) are written straight to the data channel by the transfer system, so they never passed through the send path's verification gate on receipt. Sending was already gated; receiving now is too, so an unverified peer cannot open transfers, push chunks or drive transfer state before the SAS has been compared. User consent remains required on top of this.
- **Anti-replay is actually enforced.** The sequence-number and AAD validators were defined on the wrong class (`SecureKeyStorage` instead of the connection manager), so every call site silently failed and the sliding replay window never ran. They now live on the manager, the live chat path validates the authenticated sequence number of each message, and a missing or non-numeric sequence number fails closed instead of sailing through the range checks.
- **Stale sequence numbers are rejected** rather than logged and decrypted anyway.
- **Tighter CSP.** `connect-src` and `img-src` no longer allow arbitrary `https:` hosts (nothing in the app talks to a third party), and `base-uri 'none'` is set. This removes the exfiltration channel an injection would otherwise have.
- The SAS is no longer written to logs, and the peer-announced code is compared in constant time on every path.
- Fixed `SecureMasterKeyManager.isUnlocked()` testing a field renamed long ago, so it never actually gated anything.

### Added

- Regression tests covering the verification gate and inbound frame authentication (`tests/verification-gate.test.mjs`, `tests/inbound-frame-authentication.test.mjs`).

## v5.5.0 — Encrypted voice & video calls

SecureBit now supports **end-to-end encrypted voice and video calls** — the "5.5 Secure Voice & Calls" roadmap milestone.

### Added

- **Voice & video calls.** Start a call from the chat header (phone / camera buttons). Audio and video tracks ride the **same RTCPeerConnection as the chat**, bundled onto one **DTLS-SRTP** transport — so media is end-to-end encrypted with the very connection that in-person **SAS verification** authenticated. Call setup (SDP offer/answer) is renegotiated **in-band over the verified data channel**, never through a signalling server, so the media's DTLS fingerprints are authenticated end-to-end too. There is no server that can see or MITM a call.
- **Verification-gated.** Calls are only permitted once a session is **connected and SAS-verified**; the manager rejects call signalling otherwise. The header call buttons stay disabled until then.
- **In-call controls.** Mute / unmute, camera on/off (turning the camera on during a voice call upgrades it to video in-band), front/back camera flip, minimize-to-widget (chat stays usable) and hang up. Incoming calls show an accept / decline prompt.
- **Adaptive audio codec.** Opus tuned for real-world links — in-band FEC, DTX and RED redundancy (RED preferred first where the browser advertises it) keep speech intelligible under 15–20% packet loss. Audio is bandwidth-prioritised and is **never** throttled by the network controller.
- **Adaptive video codec.** VP9 / AV1 single-encoding **SVC** (with H.264 / VP8 fallback), so video degrades gracefully by spatial/temporal layer on a weak link. A runtime `NetworkAdaptationController` reads `getStats()` every second and trims video bitrate on loss/RTT, recovering as the link clears — no renegotiation, no track restart.
- **Live connection-quality indicator.** Excellent → Good → Fair → Weak, surfaced in the voice overlay, video top bar and minimized widget. Codec tunables and their rationale are documented in [`doc/CALLS.md`](doc/CALLS.md).

### Security

- Media inherits the session's DTLS-SRTP encryption; SDP is exchanged only over the ECDH + SAS-authenticated data channel. No new ICE or signalling server is introduced — calls reuse the existing verified transport.

## v5.4.5 — Encrypted voice messages

SecureBit now supports **end-to-end encrypted voice messages**, sent over the same secure transfer channel as files.

### Added

- **Voice messages.** Record a note in the browser and send it over the existing chunked, AES-GCM-encrypted file-transfer pipeline, so it inherits the same per-file session key and SHA-256 integrity check. Audio is captured as raw PCM and encoded to **WAV**, so it plays back on every platform — including iOS/Safari. Duration and a downsampled waveform travel as unsigned presentation metadata; the audio bytes stay integrity-protected by the signed file hash.
- Voice notes are **auto-accepted** on the receiver (no consent prompt) and played **inline** from an in-memory blob — nothing is written to disk. The bubble shows an upload/download progress ring, a seekable waveform, play/pause and duration, and the usual Encrypted/Decrypted status.
- **Composer.** A mic button records a note with a live waveform and timer plus discard / send controls. On desktop the mic and send buttons sit side by side; on mobile the mic swaps to a send button as soon as you type text.

### Changed

- Content Security Policy `media-src` now allows `blob:` so recorded and received audio can be played back.
- Version scheme moved to the 5.x line (Desktop Edition = **5.0**). The roadmap gains a **5.5 "Secure Voice & Calls"** milestone (encrypted voice messages, audio calls, video calls); later milestones shift accordingly.

## v4.9.0 — Full redesign + reworked offline mode

A ground-up visual redesign of the whole application surface — landing page, "Why unique" / partners / roadmap / community sections, connection setup, in-chat header, real-time security verification report, file transfer, and the PWA install / update / offline / install-guide dialogs.

Offline experience reworked with store-and-forward over the live P2P channel:

- Messages sent while offline are queued (single ✓) and transmitted on reconnect, preserving their original send time.
- Messages to an offline peer stay at one check until that peer returns; the offline client holds them back and surfaces them on reconnect with a notice.
- WhatsApp-style per-message delivery status (sending → sent → delivered, plus a "not sent" state) via an authenticated delivery-receipt control message.
- Browser offline state no longer leaks into the P2P connection indicator.

Resilient file transfer: per-chunk segmented progress, receiver-driven retransmission of missing chunks with auto-resume after a connection blip, corrected receive rate limits, and automatic save on completion.

## v4.8.21 — Redesigned chat surface

A full visual refresh of the connected chat experience, ported from the SecureBit Chat design. No protocol, crypto or message-handling changes — only the presentation layer of the chat screen.

### Changed

- **Message bubbles** redesigned: tighter dark surface (`#0f0f11` canvas, `#26262b` sent / `#161618` received), asymmetric corner radii, monospace timestamps, and a compact per-message status row showing **Encrypted** / **Decrypted** with a lock glyph.
- **View-once** now uses a Telegram-style blurred cover with an SVG grain overlay and a centered "View once · tap to reveal" prompt; after reveal it shows a "Viewed once" tag and still burns after the sender-chosen window.
- **Disappearing timers** render a live `mm:ss` countdown in the message meta in brand orange.
- **Composer** rebuilt: inline `Send files` / `Code` / `View once` / `Timer` chips with active states, inline time-picker rows (view-once: Off/5s/10s/30s/1m, timer: Off/5s/30s/1m/1h/24h), an auto-growing message field, an "Encrypted on your device" affordance, a live character counter, and an orange send button.
- **Handshake summary** card at the top of a verified chat (collapsible): transport / cipher / key-exchange / integrity facts plus the safety number (key fingerprint).
- Fonts are mapped to the self-hosted **Inter** + system monospace stack rather than loading Google Fonts, preserving the look without an external request from a privacy-focused client.

## v4.8.20 — Secure chat tools: completed, fixed and polished

Completes the messaging controls introduced in v4.8.14 and fixes the bug that made them appear broken for recipients. All per-message options travel inside the encrypted message envelope (never in the sanitized text), so message content cannot spoof or corrupt them.

### Fixed

- **Per-message metadata was silently dropped for recipients.** `NotificationIntegration` wrapped both `webrtcManager.onMessage` and `webrtcManager.deliverMessageToUI` with two-argument shims that called the originals without the third argument (`meta`). With notifications enabled, every received message lost its `meta`, so view-once, disappearing timers and unsend all failed on the recipient side. Both wrappers now forward all arguments (`...rest`). Added `tests/notification-meta-forwarding.test.mjs`.
- **Chat would not open after SAS** (regression from the initial wiring): the composer props were threaded into the wrong component (`EnhancedConnectionSetup` instead of `EnhancedChatInterface`), throwing `ReferenceError: nowTick` on the verified-state re-render. Props are now on the chat component.

### Changed

- **Code blocks** now include lightweight, dependency-free syntax highlighting (comments, strings, numbers, keywords) rendered via React nodes — no `innerHTML`, no remote scripts. Enabling code mode expands the input (monospace, 8 rows) for comfortable entry. Copying a block auto-clears the clipboard after ~30s.
- **View-once** is now configurable: the sender picks how long the message stays visible after the peer opens it (5s / 15s / 30s / 1m) via `meta.onceTtl` (clamped 1s–1h).
- **Disappearing timer** uses a duration picker (Off / 30s / 5m / 1h) instead of click-cycling.
- **Composer toolbar** moved next to the "Send files" control; borderless buttons with the brand-orange (`accent-orange`) active state; time pickers open upward and are sized for mobile readability.
- Sender bubble background lightened to `rgba(249, 115, 22, 0.05)`.

### Removed

- **Panic wipe** button. Disconnecting already wipes keys and clears session state, so a separate panic control was redundant.

## v4.8.15 — Fix: chat would not open after SAS in v4.8.14

### Fixed

- The secure chat failed to open after both peers confirmed the SAS code: the message list and composer (in `EnhancedChatInterface`) referenced `nowTick`, `onUnsendMessage` and the new composer props, but those were threaded into the sibling `EnhancedConnectionSetup` component by mistake. At runtime this threw `ReferenceError: Can't find variable: nowTick` during the verified-state re-render, so the chat never rendered. The new props are now destructured and passed on `EnhancedChatInterface`, where the chat UI actually lives. No behavioural change to the v4.8.14 features otherwise.

## v4.8.14 — Secure chat tools: code blocks, view-once, disappearing, unsend, panic

Adds privacy-focused messaging controls. Per-message metadata (id, view-once, timer) travels **inside the encrypted message envelope**, never in the sanitized text, so message content cannot spoof or corrupt these controls. The unsend/delete signal travels over the authenticated DTLS control channel like other system messages.

### Added

- **Code blocks.** A composer button wraps the message in a fenced block; both peers render it as a monospace code window with a copy button. The marker travels as ordinary text, and the window is built from already-sanitized text via React nodes only (no `dangerouslySetInnerHTML`), so there is no new XSS surface.
- **Clipboard auto-clear.** Copying a code block clears the clipboard after ~30s — only when it can confirm the clipboard still holds the copied value, or cannot read it back, so a later copy is never clobbered.
- **View-once messages.** The recipient sees a blurred bubble that reveals on tap and is then wiped. Honestly cooperative (a malicious client or a screenshot can still capture it) — this is hygiene, not a guarantee.
- **Disappearing messages.** An optional sticky timer (30s / 5m / 1h) auto-deletes a message on both sides, with a live countdown. The incoming timer value is clamped to [5s, 24h].
- **Unsend (delete for everyone).** Removes your message locally and asks the peer to drop it via a `message_delete` control message (`MESSAGE_TYPES.MESSAGE_DELETE`).
- **Panic wipe.** One button clears the conversation, wipes keys (`_secureWipeKeys`) and tears down the session, behind a confirm prompt.

### Security

- New per-message metadata is whitelisted and bounded by `_sanitizeMessageMeta` on both send and receive; unknown fields, wrong types and out-of-range timers are dropped.
- AAD/replay protection, the SAS verification gate and receive-side DOMPurify sanitization are unchanged.

### Tests

- Added `tests/secure-chat-features.test.mjs` covering metadata sanitization, meta delivery to the UI, and the unsend control path. Full suite: 17 files, all passing.

## v4.8.13 — Message integrity & transport hardening

Security review follow-up. The end-to-end cryptography (ECDH, AES-GCM, PBKDF2, SAS bound to DTLS fingerprints, anti-replay) was verified sound; these changes fix availability/integrity defects on the send path and tighten transport headers and logging.

### Fixed

- Outgoing messages were silently rejected by an over-broad keyword blocklist in `_validateInputData`. Plain words such as "constructor", "global", "document.", "prototype", or the literal text "javascript:" caused `sendSecureMessage` to throw, so legitimate messages never reached the peer. The blocklist provided no real protection: XSS is enforced at the rendering boundary by the receive-side DOMPurify pass and by `sanitizeMessage()` before encryption. The send-path blocklist was removed.
- `_sanitizeInputString` collapsed all whitespace (`/\s+/g` to a single space), destroying multi-line messages and code snippets (`"a\nb\nc"` became `"a b c"`). Newlines, tabs and indentation are now preserved; only control characters are stripped and runs of 3+ blank lines are collapsed to two.
- AAD validation failures logged the raw AAD string, which carried `sessionId` and `keyFingerprint`. Both the message and file-message validators now log only the AAD length.

### Security

- Added `Strict-Transport-Security` (`max-age=63072000; includeSubDomains; preload`) to `deploy/nginx.conf` and `.htaccess`, closing the first-visit SSL-strip window that `upgrade-insecure-requests` alone does not cover.
- Added a restrictive `Permissions-Policy` (`camera=(self)` for in-page QR scanning; microphone, geolocation, payment, usb and sensors denied).

### Tests

- Added `tests/outgoing-message-integrity.test.mjs` covering keyword acceptance, multi-line/indentation preservation, control-character stripping, blank-line collapsing, and the size limit.

## v4.8.12 — Chat notification & file-transfer UI fixes

Fixes duplicated chat output and a layout overflow in the message list.

### Fixed

- A received file was announced many times in the chat instead of once. The per-transfer lock used a single `if` check, so when 3+ chunk operations queued on the same file they ran concurrently and broke assembly atomicity. The lock now serializes correctly, and file assembly is idempotent, so `File received` is shown exactly once per file.
- System messages were duplicated during connection setup (e.g. "Both parties confirmed!" and "Secure connection successfully established"). `handleVerificationBothConfirmed` now bails out if both confirmations were already recorded, so the message and the verified transition fire only once.
- The DTLS fingerprint (a long unbroken string) overflowed the chat bubble. The message text container now uses `min-w-0` so the fingerprint wraps within the bubble.
- Site header, init banner, and manifest now report the current version.

## v4.8.11 — File transfer reliability fix

Fixes file transfers that silently failed to reach the peer, and relaxes the overly strict file-type check that rejected legitimate files.

### Fixed

- File chunks are now sized so the on-the-wire message stays under the 64 KB SCTP message-size limit enforced by WebRTC. Previously each 64 KB chunk became a ~87 KB encrypted+Base64 message that exceeded this limit, so the consent handshake succeeded but no data was ever delivered — most visibly on Safari and cross-browser connections whose SDP omits `a=max-message-size`. The send chunk size is now 16 KB (~22 KB on the wire); inbound chunks up to 64 KB are still accepted for backward compatibility.

### Changed

- File-type validation is now driven by the extension allow-list, with the (client-supplied, easily spoofed) MIME type treated as an advisory signal. Files with a missing MIME type or a cross-OS MIME variant (e.g. `application/x-zip-compressed` for `.zip`, `image/jpg` for `.jpg`) are no longer rejected. Blocked executable/script extensions, a blatantly foreign MIME on a safe extension, and per-type size limits are still enforced.

## v4.8.10 — User-configurable STUN/TURN servers

Adds optional, advanced control over WebRTC connectivity for power and privacy-focused users. Public servers remain the zero-config default.

### Added

- "Advanced network settings" panel (header gear icon and the connection-creation screen) where users can supply their own STUN/TURN servers instead of the bundled public defaults.
- Allowlist-based validation of user input: only `stun:`/`stuns:`/`turn:`/`turns:` URLs with valid hosts are accepted; `javascript:`, `data:`, `http(s):`, `ws(s):`, control characters, and oversized input are rejected before anything reaches `RTCPeerConnection`.
- Optional on-device persistence, encrypted at rest with a non-extractable AES-GCM device key in IndexedDB, with an explicit save prompt and a "Forget saved" action.
- "Test servers" button that gathers ICE candidates against the entered configuration and reports STUN/TURN reachability.
- Privacy guidance in the panel: a TURN relay sees peer IPs and traffic timing (never message contents), so only a trusted/self-hosted relay improves privacy.

### Changed

- Relay-only privacy mode now lives in the advanced settings panel. The standalone relay-only toggle on the start screen was removed to declutter the initial view.
- Server selection priority: user custom servers > operator override (`config/ice-servers.js`) > built-in public defaults.

## v4.8.9 — Security hardening patch

This release closes a vulnerable dependency, removes committed TURN credentials, and tightens production logging.

### Security

- Upgraded DOMPurify from 3.4.4 to a patched release, resolving a high-severity XSS advisory (GHSA-87xg-pxx2-7hvx) in the incoming-message sanitizer.
- Upgraded the `esbuild` build dependency to clear a high-severity advisory in the toolchain. `npm audit` now reports zero vulnerabilities.
- Stopped tracking `config/ice-servers.js` (operator TURN credentials) in Git and added `config/ice-servers.example.js` as a template. Operators must rotate any previously committed credentials.
- Removed temporary debug branches from the production logger so it no longer prints error context or info/debug payloads — only an opaque error code.

### Documentation

- Updated the supported-release table in `SECURITY.md` to the v4.8.x line.
- Synchronized the version string across the header, manifest, README, and in-app initialization message.

## v4.8.8 — File transfer consent fix

This patch completes the mandatory receiver-consent gate for incoming file transfers and resolves a callback ownership conflict that caused every incoming file request to be silently auto-rejected.

### Fixed

- Wired up the missing fourth `onIncomingFileRequest` callback in the main `setFileTransferCallbacks` call. Without it, `handleFileTransferStart` always saw `null` for the consent handler and auto-rejected every incoming file silently.
- Removed independent callback registration from `FileTransferComponent`. The component was overwriting the application-level callbacks on mount and nulling all four on unmount, which destroyed the progress, received, and error handlers whenever the panel was hidden.
- Centralized incoming-consent state (`pendingIncomingFiles`) in the root application component so consent prompts appear regardless of whether the file-transfer panel is currently visible.
- Auto-opens the file-transfer panel when an incoming request arrives so the user sees the Accept / Reject prompt immediately.
- Added `getReceivedFileObjectURL` / `revokeReceivedFileObjectURL` helpers to `EnhancedSecureWebRTCManager` so the panel can offer a download button for completed transfers without relying on captured callback closures.
- Updated `file-transfer-ui-cleanup` regression test to match the new single-owner callback architecture.

### Security

No change to the cryptographic or transport-level security model. Sender chunks are still gated behind an explicit `file_transfer_response` from the receiver before any data is transmitted.

### Verification

- `npm test` — all 14 tests pass.
- `npm run build` — clean production build.

## v4.8.7 — WebRTC manual join reliability patch

This patch improves manual WebRTC setup across separate devices and restrictive local networks.

### Fixed

- Stabilized the manual offer/answer join flow so verification waits for real transport readiness.
- Preserved generated response data during manual exchange instead of resetting the joiner screen prematurely.
- Preserved pending creator-side offer context so responses can be applied after transient ICE failures without false session-salt hijacking errors.
- Added operator ICE override support through `config/ice-servers.js`.
- Added ExpressTURN TURN/STUN configuration for relay fallback in environments where mDNS host candidates cannot connect.
- Added user-visible warning when a remote peer provides only mDNS host candidates and no `srflx` or `relay` route.
- Added safer ICE diagnostics that report candidate classes without exposing full IP addresses or TURN credentials.

### Verification

- `npm test`
- `npm run build`

## v4.8.7 — Security hardening patch release

This patch release strengthens SecureBit.chat across verification, sanitization, privacy, transport abuse resistance, cache safety, and repository hygiene.

### Security hardening

- Bound SAS verification to the actual DTLS fingerprint strings of both peers.
- Replaced regex-based chat sanitization with DOMPurify-backed sanitization.
- Made WebRTC privacy mode explicit and kept relay-only state synchronized at runtime.
- Removed production exposure of internal debug/control hooks.
- Added receiver-side rate limiting for inbound chat messages.
- Added receiver-side throttling for inbound file chunks.

### Runtime and privacy safety

- Hardened service-worker caching so only explicitly allowlisted safe assets are cached.
- Removed an untracked disconnect timer so teardown no longer leaves delayed callbacks behind.
- Preserved relay-only TURN behavior while making privacy implications clearer when relay-only mode is disabled or TURN is unavailable.

### Repository hygiene

- Stopped tracking `node_modules` in Git so platform-specific dependency binaries no longer pollute the repository or break cross-platform builds.

### Validation

- Full regression suite passes.
- Clean install succeeds with `npm ci`.
- Production build succeeds with `npm run build`.

## v4.8.7 — Security hardening release

This release consolidates several months of security, privacy, and lifecycle hardening work by the SecureBit.chat team.

### Security

- Added mandatory interactive SAS verification; passive click-through confirmation is no longer sufficient.
- Made SAS computation deterministic across peers using shared session material.
- Enforced protocol version `4.1` mismatch handling for incompatible clients.
- Added TURN relay-only privacy mode and explicit warnings when TURN is unavailable.
- Encrypted sensitive IndexedDB metadata and added safe lazy migration for legacy plaintext records.
- Added mandatory consent gating for every incoming file transfer.
- Replaced broad file acceptance with an explicit file-type allowlist and spoofing checks.
- Sanitized every incoming decrypted chat message before UI delivery.

### Reliability and resource lifecycle

- Consolidated disconnect behavior into one canonical cleanup path.
- Added cleanup for tracked timers, deferred retries, peer-disconnect scheduling, and fake/decoy traffic.
- Rejected pending sender consent promises immediately during cleanup.
- Bounded retained received-file buffers and added graceful handling for expired download handles.
- Cleared React file-transfer UI state and detached live callbacks on unmount.
- Improved reconnect hygiene and stale-session cleanup behavior.

### Maintenance

- Pinned dependency versions.
- Applied safe transitive patch/minor updates.
- Verified a clean `npm audit` result.
- Expanded regression coverage for SAS, file consent, sanitization, privacy mode, metadata encryption, cleanup, and callback lifecycle behavior.
