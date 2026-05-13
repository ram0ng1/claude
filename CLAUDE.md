# CLAUDE.md — Flarum v2 Extension Security & Structure Playbook

**Self-contained reference loaded automatically by Claude Code in this directory.** Read
the relevant sections before adding, refactoring, or reviewing code in any Flarum v2
extension. Canonical patterns are sourced from the **official Flarum v2 first-party
extensions** installed in `vendor/flarum/*` (tags, likes, mentions, subscriptions,
suspend, gdpr, flags, nicknames) — these are the in-tree reference implementations
every extension author should mirror. See §34 for the per-pattern citation index.

This file does not depend on any other doc. Everything an AI assistant needs to write
secure Flarum v2 extensions is below.

Base Github: https://github.com/ram0ng1/verified, https://github.com/ram0ng1/avocado, https://github.com/ram0ng1/stickers

---

## Table of contents

- §0 Self-audit prompts — answer before any change
- §1 Flarum v2 architecture map (and v1 → v2 deltas LLMs get wrong)
- §2 Authorization layer 1 — `extend.php`, routes, middleware
- §3 Authorization layer 2 — endpoints, controllers, policies
- §4 Group IDs & permission grants (the GUEST trap)
- §5 Visibility scoping — `whereVisibleTo`, Discussion/Post/Tag access
- §6 API resources & Schema field visibility (data leakage)
- §7 Mass assignment & `writable()` allow-list
- §8 Extending core resources (UserResource etc.)
- §9 XSS — `m.trust`, attributes, translator strings, Blade templates, SVG
- §10 SQL injection, LIKE wildcards, filter/sort allowlists
- §11 File uploads (size, MIME, filename, disk choice)
- §12 Serving private files (headers, CSP)
- §13 **Path Traversal / Directory Traversal** — encoding bypasses, PHP quirks, canonical guard
- §14 SSRF — server-side fetch & client-side fetch
- §15 Open redirect (`?return=`/`redirect`)
- §16 CSRF & the API-token bypass trap
- §17 ApiKey / AccessToken — the master-key footgun
- §18 Throttling / rate limiting (and how to break it)
- §19 Notifications (data column leakage)
- §20 Events, console schedules, queued jobs (actor identity)
- §21 Settings — `serializeToForum` has NO visibility callback
- §22 Translator interpolation & locale conventions
- §23 Logging sensitive data
- §24 Cache keys (cross-actor cache poisoning)
- §25 Validators
- §26 Migrations (idempotency, deleting persisted settings)
- §27 Frontend `extend()` / `override()` discipline
- §28 `app.session.user`, `app.forum.attribute('headerHtml')` traps
- §29 Real-time / WebSocket broadcast leaks
- §30 Sessions, cookies, headers, GDPR
- §31 Dead-code & refactor heuristics
- §32 Final pre-commit checklist (100+ items)
- §33 Severity calibration & quick triage
- §34 **Patterns from official Flarum v2 extensions** (canonical citations)
- §35 **CI/CD & GitHub Actions workflows** — baseline (lint, release, forum post) + 🔴🟠🟡⚪ hardening roadmap (SHA pinning, harden-runner, CodeQL, Dependabot, SLSA) + Claude scaffolding prompt

---

## §0. Self-audit prompts — answer BEFORE writing or accepting any change

Walk through these. If you can't answer one, stop and investigate.

### Before you write a new endpoint, controller, or mutation
1. **Who can call this?** Guest, registered user, owner, admin? Where is that enforced?
2. **What happens if the actor passes IDs belonging to someone else?** (IDOR vector)
3. **What body fields am I reading?** Are they cast and validated, or `->fill($body)`?
4. **What HTTP method?** A `GET` that mutates state is a CSRF trap.
5. **Does the query/log/render touch any user-controlled string?** Then §9/§10/§23 apply.
6. **Is there a relation I'm including?** Did I `whereVisibleTo($actor)` it?

### Before you call `m.trust()` in JS/TS
1. **Trace the string to its source.** `app.forum.attribute(...)`, settings, API payload, DOM attribute?
2. **Is it sanitized in the backend?** If yes, mirror the allowlist in JS.
3. **Is it sanitized in JS?** Allowlist must match the backend's.
4. **Can I render without `m.trust`?** If yes, do that.
5. **Is the string a translator output with user-interpolated `{vars}`?** `m.trust(trans(..., {}, true))` is XSS.

### Before you accept a file upload / fetch a URL
1. Did I validate **size** (null + cap), **extension**, **MIME via finfo**, **store outside the webroot** if private?
2. Did I generate the **server-side filename** and **ignore** the client's filename?
3. Did I confine the read/write path with `realpath` + prefix check?
4. If fetching from the browser: same-origin check or explicit allowlist?
5. If fetching from the server: host allowlist + block RFC1918/`169.254.169.254`?

### Before you expose a Schema field, settings key, or notification payload
1. Does it contain email, IP, token, internal note, moderation comment, raw path?
2. Schema → does it have `->visible(fn(...))` gating the read?
3. Settings → is it `serializeToForum`'d? If yes, **every guest sees it** — no per-actor filter.
4. Notification → is the raw content in the `data` column? It will be returned verbatim, no policy re-check.

### Before you create an `ApiKey`, schedule a console command, or register a custom middleware
1. ApiKey with `user_id = NULL` is an **admin master key** — any caller can impersonate any user with `;userId=N`. Don't create it for "cron" or "webhooks" unless absolutely required, and document the threat model inline.
2. Console schedules run as **Guest** by default — pass an explicit admin actor if the job needs privilege.
3. Middleware calling `$next($request)` before validation discards the validation result.

### Before merging
- Run the §32 final checklist. No exceptions for "small" changes.

---

## §1. Flarum v2 architecture map

The v2 model the LLM training corpora usually get wrong. Memorize the deltas.

| Concern | Flarum v2 location | v1 → v2 delta |
|---|---|---|
| Wiring | `extend.php` returning array of `Extend\*` instances | unchanged |
| API resource | `src/Api/Resource/XxxResource.php` extends `Flarum\Api\Resource\AbstractDatabaseResource` | **replaces** v1 `AbstractSerializer` + `Extend\ApiSerializer` |
| CRUD endpoints | declared inside `Resource::endpoints()` via `Endpoint\Show/Index/Create/Update/Delete::make(...)` with fluent `->authenticated()/->can()/->admin()` | **replaces** v1 `AbstractCreateController` etc. + `Extend\ApiController` |
| Custom endpoints | `Endpoint\Endpoint::make('myext.action')->route('POST', '/{id}/act')->action(fn($context) => …)` | NEW; alternative to dedicated controller |
| Field schema | `Resource::fields()` returns `Schema\Str / Boolean / Integer / Number / Date / DateTime / Arr / Relationship\ToOne / ToMany` | **replaces** `getDefaultAttributes()` |
| Field-level access | `->visible(fn(...))`, `->writable(...)`, `->writableOnCreate()`, `->property('column')`, `->required()`, `->maxLength()`, `->in()`, `->rule()`, `->nullable()` | NEW shape; `assertCan` 2nd param renamed `$arguments` (mixed) — was `$resource` in v1 |
| Classic controllers | `implements Psr\Http\Server\RequestHandlerInterface` + `Extend\Routes('api')->post(...)` | still valid for non-CRUD (upload, import, export) |
| Actor / auth | `Flarum\Http\RequestUtil::getActor($request)` → `->assertRegistered() / ->assertCan(string $ability, mixed $args = null) / ->assertAdmin()` | unchanged shape; `assertAdmin()` = `assertCan('administrate')` |
| Policy | `Flarum\User\Access\AbstractPolicy`, wired via `Extend\Policy()->modelPolicy()/->globalPolicy()`; constants `ALLOW/DENY/FORCE_ALLOW/FORCE_DENY` | unchanged; priority `FORCE_DENY > FORCE_ALLOW > DENY > ALLOW` |
| Validator | `Flarum\Foundation\AbstractValidator` with `$rules`, wired via `Extend\Validator(...)->configure(...)` | unchanged |
| Settings | `Extend\Settings()->serializeToForum('camelKey', 'ext-slug.dot.key', 'cast', $default)` | unchanged; **no per-actor visibility callback** (§21) |
| Locales | `new Extend\Locales(__DIR__.'/locale')` + `locale/en.yml` keyed by `<ext-slug>:` | unchanged |
| Migrations | `migrations/<date>_<name>.php` returning `['up' => fn(Builder $schema) => …, 'down' => fn(…) => …]` | unchanged |
| Formatter | `Extend\Formatter()->configure(...)->parse(...)->render(...)->unparse(...)` (s9e/TextFormatter pipeline) | unchanged |
| CSRF | `Flarum\Http\Middleware\CheckCsrfToken` — body `csrfToken` OR header `X-CSRF-Token`, `hash_equals` against session; bypasses GET/HEAD/OPTIONS | unchanged; **bypassed entirely by token auth** (§16) |
| Frontend wiring | `Extend\Frontend('forum'\|'admin')->css(...)->js(...)->content(fn(...) => …)` | unchanged |

**No `$fillable` / `$guarded` on `Flarum\Database\AbstractModel`.** Mass-assignment defense
lives in the Schema `writable()` allowlist (§7), **not** in the model. Never pass
`$request->getParsedBody()` to `Model::fill()`.

---

## §2. Authorization layer 1 — `extend.php`, routes, middleware

### Locate

```bash
rg -n "new Extend\\\\|Extend\\\\\\w+\\(" extend.php
rg -n "Extend\\\\Routes|Extend\\\\Middleware" extend.php
```

### Red flags

- A `Routes('api')->post(...)` whose controller does NOT call
  `RequestUtil::getActor(...)->assertRegistered()` (or stricter) as its first action.
- `Extend\Middleware('api')->add(...)` that calls `$next($request)` BEFORE validation.
- A controller that sets `$request = $request->withAttribute('bypassCsrfToken', true)`
  outside of explicitly token-authenticated paths.
- A route registered via `->get(...)` whose handler mutates state. Use `POST`/`PATCH`/`DELETE`.

### Correct shape

```php
return [
    (new Extend\Routes('api'))
        ->post('/myext/import', 'myext.import', ImportController::class),
];

// Controller — second defense layer, NEVER rely only on middleware
public function handle(ServerRequestInterface $request): ResponseInterface
{
    $actor = RequestUtil::getActor($request);
    $actor->assertRegistered();
    if (! $actor->isAdmin()) throw new PermissionDeniedException();
    // …
}
```

Reference shape: official `flarum/tags` admin-only OrderTagsController calls
`RequestUtil::getActor($request)->assertAdmin()` as its first line —
[vendor/flarum/tags/src/Api/Controller/OrderTagsController.php:24](../../vendor/flarum/tags/src/Api/Controller/OrderTagsController.php#L24).

---

## §3. Authorization layer 2 — endpoints, controllers, policies

Flarum v2 gives you **two enforcement layers** for every mutation: the endpoint/route
layer (declarative) and the controller/handler layer (imperative). **Use both.**

### Endpoint layer (preferred for CRUD inside a Resource)

```php
// src/Api/Resource/MyResource.php
public function endpoints(): array
{
    return [
        Endpoint\Index::make()->can('administrate'),
        Endpoint\Create::make()->can('administrate'),
        Endpoint\Update::make()->can('administrate'),
        Endpoint\Delete::make()->can('administrate'),

        Endpoint\Endpoint::make('myext.act')
            ->route('POST', '/{id}/act')
            ->authenticated()
            ->can('act')                                          // runs assertCan('act', $context->model)
            ->action(function (Context $context) {
                $resource = $context->model;
                // mutate $resource
            })
            ->response(fn () => new EmptyResponse(204)),
    ];
}
```

Reference shape from `flarum/gdpr` — `ErasureRequestResource::endpoints()` chains
`authenticated()->can('cancel')->action(...)` then returns `EmptyResponse(204)`:
[vendor/flarum/gdpr/src/Api/Resource/ErasureRequestResource.php:100](../../vendor/flarum/gdpr/src/Api/Resource/ErasureRequestResource.php#L100).

- `->authenticated(bool|Closure)` — requires non-guest.
- `->can(string $ability)` — runs `assertCan($ability, $context->model)`.
- `->admin()` — equivalent to `->can('administrate')`.

### Controller layer (for non-CRUD: upload, import, export)

```php
public function handle(ServerRequestInterface $request): ResponseInterface
{
    $actor = RequestUtil::getActor($request);
    $actor->assertRegistered();                                // throws NotAuthenticatedException for guests

    $resourceId = (int) ($request->getQueryParams()['id'] ?? 0);
    if ($resourceId <= 0) throw new ValidationException(['id' => 'invalid']);

    $isSelf = (int) $actor->id === $resourceId;                // STRICT compare — null == 0 is TRUE in PHP
    if (! $isSelf) $actor->assertCan('myext.act_on_others');

    // Mutating POST: require admin even for self-targeted, unless explicit
    if (! $isSelf && ! $actor->isAdmin()) throw new PermissionDeniedException();
}
```

### Policy layer

```php
class MyPolicy extends AbstractPolicy
{
    public function update(User $actor, MyModel $model)
    {
        if ((int) $actor->id === (int) $model->user_id) return $this->allow();
        if ($actor->isAdmin())                          return $this->allow();
        return null;     // abstain — let the chain run. DON'T return deny()
                         // unless you mean "veto even if another policy would allow".
    }
}

// extend.php
(new Extend\Policy())->modelPolicy(MyModel::class, MyPolicy::class)
```

Reference: `flarum/tags` `TagPolicy::can()` returns `deny()` / `allow()` / `null` —
[vendor/flarum/tags/src/Access/TagPolicy.php:18](../../vendor/flarum/tags/src/Access/TagPolicy.php#L18).
Wired side-by-side with `globalPolicy()` at
[vendor/flarum/tags/extend.php:125](../../vendor/flarum/tags/extend.php#L125).

Priority chain: `FORCE_DENY > FORCE_ALLOW > DENY > ALLOW`. `forceAllow`/`forceDeny`
override every other policy — use ONLY for true sudo paths (site kill switch). Document
inline.

### Red flags (`rg`)

```bash
rg -n "implements RequestHandlerInterface|Endpoint\\\\(Create|Update|Delete|Endpoint)" src/
rg -n "forceAllow|forceDeny" src/
rg -n "actor->id\\s*==\\s*\\\$|->id\\s*==\\s*\\(int\\)" src/        # loose compare
```

- Loose `==` comparing actor id to resource id. `null == 0 === true` → guests act as user 0. Always `===` after `(int)` on both sides.
- Policy returning `$this->allow()` without checking `actor->id === resource.user_id`.
- Policy gating on a nullable FK (e.g. `$discussion->first_post_id`). When FK is null, the check short-circuits and over-allows. **Historical**: CVE-2023-22489 in flarum core.
- `forceAllow()` without an inline comment justifying the override.
- A `->can('view', $model)` immediately followed by `$model->relation()->get()` without `whereVisibleTo($actor)` on the relation.

### Known CVEs to learn from
- **CVE-2023-22487** (flarum/framework): forgotten visibility check on included relations leaked data.
- **CVE-2023-22489** (flarum/framework): null-FK policy bypass.
- **CVE-2024-21641** (flarum/framework): open redirect via login `?return=`.

---

## §4. Group IDs & permission grants (the GUEST trap)

```
Group::ADMINISTRATOR_ID = 1
Group::GUEST_ID         = 2     ← anonymous, NOT "logged-in users"
Group::MEMBER_ID        = 3     ← every authenticated user
Group::MODERATOR_ID     = 4
```

`User::hasPermission` walks the union of the actor's groups. **Guest = group 2**. Any
permission granted to GUEST is granted to **the entire internet**.

### Red flags

```bash
rg -n "Group::GUEST_ID|->id\\s*=\\s*2|group_id.*2[^0-9]" migrations/ src/
```

- A migration seeding `permissions` rows with `group_id = 2` for anything beyond
  `viewForum`/`signUp` (the default reads).
- A custom permission registered without a default group restriction — admins must
  explicitly opt-in groups via the admin UI; if your extension does it programmatically,
  default to `MEMBER_ID` (3), never GUEST.

### Correct shape (migration)

```php
$db->table('group_permission')->insert([
    ['group_id' => Group::MEMBER_ID, 'permission' => 'myext.usePicker'],
    ['group_id' => Group::MODERATOR_ID, 'permission' => 'myext.moderate'],
]);
```

---

## §5. Visibility scoping — `whereVisibleTo`, Discussion/Post/Tag access

`whereVisibleTo($actor)` is the single bottleneck preventing IDOR on `Discussion`,
`Post`, `User`, `Group`, `AccessToken`, `Notification`. It walks every registered
`ScopeVisibility` for the model.

Implementation: `Flarum\Database\ScopeVisibilityTrait::scopeWhereVisibleTo` — walks
parent classes' scopers IN ORDER, then child. Models with the trait include the five
above plus anything that opts in via `Extend\ModelVisibility`.

### Red flags

```bash
rg -n "Discussion::find\\(|Post::find\\(|User::find\\(" src/
rg -n "->discussions\\(\\)|->posts\\(\\)" src/
```

For each hit, the call MUST be one of:
- `Discussion::whereVisibleTo($actor)->find($id)` — for fetches.
- `$discussion->posts()->whereVisibleTo($actor)->get()` — for relations.
- Inside a Policy/Endpoint that has already gated `view` ability — then the fetch can
  trust the policy.

### Tag access cascades (when `flarum/tags` is enabled)

`TagPolicy::can` denies if a tag is restricted AND the actor lacks `tag{id}.{ability}`
permission. `DiscussionPolicy` (under flarum/tags) propagates: ANY restricted tag on the
discussion that the actor can't access denies the whole discussion. Your extension that
loads discussions MUST honor this by using `whereVisibleTo` and NEVER by direct
`Discussion::where('id', $id)`.

### Correct shape

```php
$discussion = Discussion::whereVisibleTo($actor)->find($id);
if ($discussion === null) throw new RouteNotFoundException();
$posts = $discussion->posts()->whereVisibleTo($actor)->orderBy('number')->get();
```

---

## §6. API resources & Schema field visibility (data leakage)

### Locate every field

```bash
rg -n "Schema\\\\(Str|Integer|Boolean|Number|Date|DateTime|Arr|Relationship)" src/ -A1
```

### Red flags — fields that MUST have `->visible(...)`

- Email, phone, IP, last-login timestamp, raw filesystem path, internal note, moderation
  comment, foreign-system ID, password hash (yes, people accidentally expose these).
- Token columns (`api_token`, `password_reset_token`, `email_confirmation_token`).
- Relationships loading entire `User` resources when only `displayName`/`avatarUrl` is
  needed — leaks email/preferences. Trim with a custom `ToOne` that includes only what
  you need.
- Computed `->get(fn ($model, Context $ctx) => …)` that ignores the actor.
- `Schema\Boolean::make('isAdmin')` — only included for **self** in core's UserResource
  ([UserResource.php:292](../../vendor/flarum/core/src/Api/Resource/UserResource.php#L292)).
  Don't expose admin status of OTHER users.

### Correct shape (PII gating)

```php
Schema\Str::make('documentPath')
    ->property('document_path')
    ->visible(function ($request, Context $context) {
        $actor = $context->getActor();
        return $actor->isAdmin() || (int) $actor->id === (int) $request->user_id;
    }),

Schema\Str::make('email')
    ->writable(fn($u, Context $c) => $c->getActor()->can('editCredentials', $u) || (int)$c->getActor()->id === (int)$u->id)
    ->visible(fn($u, Context $c) => $c->getActor()->can('editCredentials', $u) || (int)$c->getActor()->id === (int)$u->id),
```

References from official extensions:
- `flarum/tags` hides admin-only state with `->visible(fn (Tag $tag, FlarumContext $context) => $context->getActor()->isAdmin())` —
  [vendor/flarum/tags/src/Api/Resource/TagResource.php:114](../../vendor/flarum/tags/src/Api/Resource/TagResource.php#L114).
- `flarum/suspend` reuses one `$canSuspend` closure for BOTH `visible()` and `writable()` —
  [vendor/flarum/suspend/src/Api/UserResourceFields.php:28](../../vendor/flarum/suspend/src/Api/UserResourceFields.php#L28).
- `flarum/likes` re-evaluates per-resource ability inside `writable()` (prevents mass-PATCH bypass) —
  [vendor/flarum/likes/src/Api/PostResourceFields.php:29](../../vendor/flarum/likes/src/Api/PostResourceFields.php#L29).

### `scope()` for resource-level row gating

For resources where users see only THEIR rows, add a `scope()` method:

```php
public function scope(Builder $query, Context $context): void
{
    $actor = $context->getActor();
    if (! $actor->isAdmin()) {
        $query->where('user_id', (int) $actor->id);
    }
}
```

Or register a global visibility scope via `Extend\ModelVisibility`:

```php
// extend.php — flarum/tags pattern
(new Extend\ModelVisibility(Tag::class))
    ->scope(Access\ScopeTagVisibility::class),
```

Reference: [vendor/flarum/tags/extend.php:133](../../vendor/flarum/tags/extend.php#L133).

---

## §7. Mass assignment & `writable()` allow-list

Flarum v2 has **NO** `$fillable` / `$guarded`. Protection is the Schema `writable()`
allowlist. Anything not marked `writable*` is **ignored on input** — that's the guard.

### Red flags

```bash
rg -n "->fill\\(|->forceFill\\(|::create\\(\\\$req|::create\\(\\\$body|->update\\(\\\$body|Arr::only\\(\\\$body" src/
rg -n "protected \\\$guarded\\s*=\\s*\\[\\]" src/
```

- `Model::create($request->getParsedBody())` / `$model->fill($body['data']['attributes'])`.
- `$model->forceFill(...)` — bypasses Eloquent guards (core sets none, but app code might).
- `protected $guarded = []` anywhere — disables Eloquent's own guard.
- Manual `setAttribute` loops over body keys.

### Correct shape

```php
$attrs = (array) ($body['data']['attributes'] ?? []);

$title  = isset($attrs['title']) ? mb_substr(trim((string) $attrs['title']), 0, 100) : '';
$reason = isset($attrs['reason']) ? mb_substr(trim((string) $attrs['reason']), 0, 1000) : null;

$model = new MyModel();
$model->user_id = (int) $actor->id;                        // server-controlled
$model->status  = MyModel::STATUS_PENDING;                 // server-controlled
$model->title   = $title;
$model->reason  = $reason ?: null;
$model->save();
```

### Per-field `writable*` examples

```php
Schema\Str::make('title')->required()->maxLength(100)->writableOnCreate(),   // POST only
Schema\Integer::make('userId')
    ->property('user_id')
    ->writable(fn($model, Context $c) => $c->getActor()->isAdmin()),
Schema\Str::make('status')->in(['pending','approved','rejected'])
    ->writable(fn($model, Context $c) => $c->getActor()->isAdmin()),
```

Anything client-controlled that influences **ownership, status, role, or pricing** must
be server-derived — not body-derived.

---

## §8. Extending core resources (UserResource, ForumResource, DiscussionResource)

When you add fields via `Extend\ApiResource(UserResource::class)->fields(fn() => [...])`,
**field visibility does NOT cascade from siblings**. Every new field defaults
`visible=true`.

### Red flag

```php
// Leaks phone to EVERY guest doing GET /api/users
(new Extend\ApiResource(\Flarum\Api\Resource\UserResource::class))
    ->fields(fn() => [
        Schema\Str::make('phone')->property('phone'),
    ])
```

### Correct shape

```php
->fields(fn() => [
    Schema\Str::make('phone')
        ->property('phone')
        ->visible(fn($user, Context $c) =>
            $c->getActor()->isAdmin() || (int)$c->getActor()->id === (int)$user->id
        )
        ->writable(fn($user, Context $c) =>
            $c->getActor()->isAdmin() || (int)$c->getActor()->id === (int)$user->id
        ),
])
```

The core pattern to mirror:
[UserResource.php:176](../../vendor/flarum/core/src/Api/Resource/UserResource.php#L176)
gates `email` to `editCredentials` or self.

---

## §9. XSS

### 9.1 `m.trust()` audit

```bash
rg -n "m\\.trust\\(" js/src/
```

For every hit, trace input to its source. If from ANY of:
- `app.forum.attribute('...')` — admin-controlled but still untrusted (admin compromise = persistent XSS).
- API response field — only safe if backend sanitizes.
- A `getAttribute('data-...')` from a DOM element produced by formatter/template.
- A `translator.trans(..., {}, true)` with user-interpolated `{vars}` — see §22.

…then there must be a sanitizer applied either backend (`htmlspecialchars` + allowlist
re-injection) AND mirrored in JS, or a strict serializer in JS before `m.trust`.

### 9.2 Mirroring pattern (PHP ↔ TS)

```php
// PHP — backend allowlist re-injection after full escape
$escaped = htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
return preg_replace(['#&lt;(/?)(strong|em|br)&gt;#i'], ['<$1$2>'], $escaped);
```

```ts
// TS — exact mirror
export function sanitize(raw: string): string {
  const escaped = (raw || '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  return escaped.replace(/&lt;(\/?)(strong|em|br)&gt;/gi, '<$1$2>');
}
```

The cleanest first-party pattern is **avoiding `m.trust` entirely** by routing through
the s9e/TextFormatter pipeline. `flarum/mentions` parses raw user input into typed
formatter tags (`USERMENTION`, `GROUPMENTION`) with attribute filterChains that coerce
inputs to `#uint`; the XSL template then renders sanitized markup — no `m.trust` needed.
See [vendor/flarum/mentions/src/ConfigureMentions.php:59](../../vendor/flarum/mentions/src/ConfigureMentions.php#L59).

When you genuinely need a mirror pair (PHP sanitizer + JS sanitizer), keep both
allowlists identical; drift between them is the most common XSS source in extensions
that ship admin-curated HTML.

### 9.3 Attribute XSS (without `m.trust`)

Mithril escapes text nodes but does NOT validate attributes like `href`, `src`, `style`,
`formaction`. For URLs from user input:

```ts
// BAD — javascript: URL fires on click
<a href={user.profileLink()}>Profile</a>

// GOOD — protocol allowlist
const safe = /^https?:\/\//i.test(user.profileLink()) ? user.profileLink() : '';
{safe && <a href={safe} target="_blank" rel="noopener noreferrer">Profile</a>}
```

For `style: url(...)` values, use a strict scheme allowlist:

```ts
function safeCssUrl(raw: string): string {
  try {
    const u = new URL(raw, location.origin);
    if (['javascript:', 'data:', 'file:', 'vbscript:'].includes(u.protocol)) return '';
    return u.href;
  } catch { return ''; }
}
```

`flarum/nicknames` also blocks markdown/email-rendering attack chars at the schema
layer with a `not_regex` rule —
[vendor/flarum/nicknames/src/Api/UserResourceFields.php:44](../../vendor/flarum/nicknames/src/Api/UserResourceFields.php#L44).
Mirror this pattern for any field that may be rendered in plain-text email (mail clients
auto-link `evil.com`).

### 9.4 Blade email templates — `{{ }}` escapes, `{!! !!}` is RAW

Core's `notification.blade.php` uses `{!! $body !!}`. If your extension passes
user-controlled content into `$body`, mail clients render the HTML.

```bash
rg -n "\\{!!" views/
```

Rules:
- Use `{{ $variable }}` for ANY user-controlled value.
- `{!! !!}` only for content that's already passed through `app('flarum.formatter')->render(...)`
  or your own sanitizer.
- Plain-text email bodies: still validate display names — mail clients auto-link `evil.com`.

### 9.5 SVG inline (`m.trust(svg)`)

If you render SVG sourced from upload, admin settings, or any user input:

1. **Sanitize on save** (DOMDocument, allowlist of tags + attributes).
2. **Sanitize again on render** (defense in depth).
3. **Reject `<!DOCTYPE>` and `<!ENTITY>` BEFORE parsing** (XXE / billion-laughs).
4. **Strip these tags unconditionally**:
   ```
   script, foreignobject, iframe, object, embed, base, link, style,
   a, animate, animatetransform, animatemotion, set, use[href^="http"]
   ```
5. **Strip `on*` attributes** and any attribute whose value starts with `javascript:`,
   `data:`, or `vbscript:`.

### 9.6 Known CVE patterns (re-introduce by accident)

- **CVE-2021-32671**: translator XSS — user-substituted `{name}` rendered via `m.trust`.
- **CVE-2026-30913**: display-name autolink in email (e.g. `john.evil.com`).
- **CVE-2026-41887**: LESS `@import` injection from admin-controlled theme settings
  reads server files into compiled CSS. If your extension exposes any setting via
  `Extend\Settings->registerLessConfigVar`, run `Flarum\Forum\ValidateCustomLess`
  server-side and reject `@import` / `data-uri()`.

### 9.7 Confirmed safe patterns in official Flarum extensions

None of the surveyed first-party extensions (`tags`, `likes`, `mentions`, `subscriptions`,
`suspend`, `gdpr`, `flags`, `nicknames`) use `m.trust(...)` directly in their JS. They
either:
- Emit s9e/TextFormatter XSL templates (mentions, markdown, bbcode) — output is
  pre-sanitized markup, parsed server-side and rendered without `m.trust`.
- Bind data-attributes on Mithril vnodes (`canTag`, `isLiked`) computed server-side via
  `Schema\Boolean::make(...)->get(fn ... => $actor->can(...))` —
  [vendor/flarum/tags/js/src/forum/addTagControl.js:7](../../vendor/flarum/tags/js/src/forum/addTagControl.js#L7).

**Rule of thumb**: if you find yourself reaching for `m.trust`, ask whether the data
could instead be expressed as a typed schema attribute + Mithril vnode tree.

---

## §10. SQL injection, LIKE wildcards, filter/sort allowlists

### Red flags

```bash
rg -n "DB::raw|whereRaw|orderByRaw|selectRaw|->raw\\(" src/
rg -n "\\\$_GET|\\\$_POST|\\\$_REQUEST" src/
rg -n "->where\\(.*'like'" src/
```

- String concatenation in `whereRaw('col = '.$input)`.
- `orderBy($request->input('sort'))` without a sort-column allowlist.
- `LIKE` without escaping `%` and `_` from user input — user forces broader-than-intended matches (wildcard injection).
- Any access to `$_GET`/`$_POST` directly. Always PSR-7: `$request->getQueryParams()`, `$request->getParsedBody()`, `$request->getUploadedFiles()`.

### Correct shape

```php
// LIKE — escape user wildcards
$needle = (string) ($request->getQueryParams()['q'] ?? '');
$like   = '%' . str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $needle) . '%';
$query->where('username', 'like', $like);

// Sort — allowlist
$allowedSorts = ['createdAt' => 'created_at', 'title' => 'title'];
$sort = $request->getQueryParams()['sort'] ?? 'createdAt';
$column = $allowedSorts[$sort] ?? 'created_at';
$query->orderBy($column);

// Raw — bind, never concat
DB::select('SELECT * FROM users WHERE email = ?', [$email]);

// Best — Query Builder always binds
User::query()->where('email', $email)->get();
```

### Search filters (`Extend\Filter` / `Extend\SearchDriver`)

Core's `FilterManager::apply` only invokes filters registered by key (allowlist is
enforced by registration). But INSIDE a filter, you still control the SQL:

```php
// BAD — raw interpolation of user value
public function filter(SearchState $state, string $value, bool $negate): void
{
    $state->getQuery()->whereRaw("title = $value");
}

// GOOD — parameter binding
public function filter(SearchState $state, string $value, bool $negate): void
{
    $clause = $negate ? '!=' : '=';
    $state->getQuery()->where('title', $clause, $value);
}
```

Note: filter values can come with a `-` prefix for negation (the FilterManager passes
`$negate`). Handle it explicitly; otherwise users invert your filter unexpectedly.

**Watch out** for filter helpers that interpolate SETTING values into raw SQL (e.g.
fulltext config names) — even admin-controlled strings should pass through an allowlist
because admin-compromise is a real threat model.

---

## §11. File uploads

### Required validations (mirror Flarum core's `AvatarUploader` — [vendor/flarum/core/src/User/AvatarUploader.php](../../vendor/flarum/core/src/User/AvatarUploader.php) — for image uploads, OR roll the full pipeline below for non-image content)

```php
public const MAX_BYTES = 8 * 1024 * 1024;
public const ALLOWED = [
    'json' => ['application/json', 'text/plain'],
    'png'  => ['image/png'],
    // …
];

public function handle(ServerRequestInterface $request): ResponseInterface
{
    RequestUtil::getActor($request)->assertAdmin();             // 1. Authorize

    $file = $request->getUploadedFiles()['file'] ?? null;
    if (! $file || $file->getError() !== UPLOAD_ERR_OK) {
        return new JsonResponse(['error' => '...'], 400);
    }

    $size = $file->getSize();                                    // 2. Size: null + cap
    if ($size === null || $size <= 0 || $size > self::MAX_BYTES) {
        return new JsonResponse(['error' => 'size'], 400);
    }

    $ext = strtolower(pathinfo((string) $file->getClientFilename(), PATHINFO_EXTENSION));
    if (! isset(self::ALLOWED[$ext])) {                          // 3. Extension allowlist
        return new JsonResponse(['error' => 'ext'], 400);
    }

    $tmp = $file->getStream()->getMetadata('uri');               // 4. Re-detect MIME server-side
    $mime = null;
    if (is_string($tmp) && is_readable($tmp) && function_exists('finfo_open')) {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        if ($finfo) { $mime = finfo_file($finfo, $tmp) ?: null; finfo_close($finfo); }
    }
    if ($mime === null || ! in_array(strtolower($mime), self::ALLOWED[$ext], true)) {
        return new JsonResponse(['error' => 'mime'], 400);
    }

    $filename = bin2hex(random_bytes(16)) . '.' . $ext;          // 5. Server-side filename
    $file->moveTo($publicOrPrivateDir . '/' . $filename);
    @chmod($publicOrPrivateDir . '/' . $filename, 0640);         // 6. Restrictive perms
}
```

### Red flags

- `$file->getSize() > $max` without `=== null` check — PSR-7 allows unknown size; cliente pode mandar chunked sem `Content-Length`.
- Validating only the extension (forgeable). Always re-detect MIME via `finfo`.
- Trusting `getClientMediaType()` — comes from the client.
- Saving inside the webroot when the file should be private (PDFs, ID documents). Always use `$paths->storage . '/myext-uploads/{userId}/...'` — outside the webroot — and serve through an authorized controller (§12).
- Keeping the client filename — always generate `bin2hex(random_bytes(16))` + sanitized extension.
- Forgetting `@chmod` — defaults may be world-readable on shared hosts.
- **Polyglot files** — PNG with embedded PHP, image with embedded SVG-XSS. CVE-2023-40033 hit Flarum core via Intervention\Image processing a URL string instead of bytes. If you use Intervention\Image, ensure you pass `$file->getContents()` (bytes), not `$file->getClientFilename()` (string), and that `allow_url_fopen=0` in PHP config.

### Disk selection

```bash
rg -n "->disk\\(|FilesystemFactory|Filesystem\\\\Manager" src/
```

- **`flarum-avatars` is a public disk.** Writing raw user bytes there exposes them via HTTP. Always re-encode through Intervention Image OR use a private disk.
- For non-image private uploads, register your own disk via `Extend\Filesystem('myext-uploads')->disk(...)` and serve through an authorized controller — never via direct URL.

---

## §12. Serving private files

### Red flags

- `header('Content-Type: ' . $file->getClientMediaType())` — client-controlled.
- No `X-Content-Type-Options: nosniff`.
- PDFs/SVGs served inline without CSP `sandbox` — PDFs embed JS; SVGs have `<a href="javascript:">` + `<animate>`.
- Filename built from `$_GET['file']` without `realpath` confinement.

### Correct shape

```php
$base     = realpath($baseDir);
$absolute = realpath($base . DIRECTORY_SEPARATOR . $relative);
if ($absolute === false || ! str_starts_with($absolute, $base . DIRECTORY_SEPARATOR)) {
    throw new RouteNotFoundException();                          // path traversal blocked
}

if (! preg_match('/^[a-f0-9]{32}\.(png|jpg|jpeg|webp|pdf)$/i', $filename)) {
    throw new RouteNotFoundException();                          // filename allowlist
}

$response = (new Response())
    ->withBody($stream)
    ->withHeader('Content-Type', $mimeFromExtension)             // server-derived, never client
    ->withHeader('Content-Disposition', 'inline; filename="document.' . $ext . '"')
    ->withHeader('X-Content-Type-Options', 'nosniff')
    ->withHeader('X-Frame-Options', 'SAMEORIGIN')
    ->withHeader('Cache-Control', 'private, no-store, max-age=0');

if ($mime === 'application/pdf') {
    $response = $response->withHeader('Content-Security-Policy', 'sandbox');
}
```

**Stripping `..` with `str_replace('..', '', $path)` is defeated** by `....//` and URL
encoding (`%2e%2e`). See §13 for the full path traversal hardening guide.

---

## §13. Path Traversal / Directory Traversal

**CWE-22.** An attacker manipulates a path string (filename, key, identifier) that the
extension concatenates into a filesystem operation, escaping the intended directory via
`../`, encoded variants, absolute paths, stream wrappers, or symlinks. In a Flarum
extension this means an HTTP request can cause the PHP process to **read, write, append,
copy, move, include, or delete** files outside the directory the extension owns —
typically `config.php`, `.env`, `storage/sessions/*`, `vendor/composer/installed.json`,
or overwriting `public/index.php` for RCE. CVE-2023-40033 and CVE-2026-41887 hit Flarum
core via this class.

### 13.1 Attack vectors in a Flarum extension context

Audit every one of these surfaces — they're all real:

- **Download / serve endpoints**: `GET /api/myext/files?name=...` → `readfile()` / `Stream::fromFile()`.
- **Delete endpoints**: admin trash, "delete my upload", scheduled cleanup commands.
- **Include / template rendering**: `include $path`, `view()->file($userInput)`, custom Twig/Blade loader with a user-controlled namespace.
- **Copy / move / rename**: avatar replacement, attachment re-organization, GDPR exports moving temp files.
- **Upload destination**: paths derived from `$file->getClientFilename()` (client-controlled string) instead of server-generated names.
- **Migrations / install hooks**: writing seed files, copying assets — run as the web user, often with broader permissions than runtime requests.
- **Console / scheduled commands**: `php flarum myext:purge --dir=...` invoked from cron with operator-supplied flags.
- **LESS / CSS compilation**: `@import` and `data-uri()` in admin-controlled settings. This is how CVE-2026-41887 worked — LESS variables flow into the LESS parser which performs file reads.
- **Webhook / API callback handlers** that persist a payload to disk under a key from the remote service.
- **Archive routines** (`ZipArchive::addFile`, `Phar::buildFromDirectory`) — zip-slip: the archive entry name itself can contain `../`.
- **Log writers** that include a request-supplied identifier in the filename.

### 13.2 Encoding bypasses you MUST defeat

A guard must canonicalize **before** comparing. Every variant below decodes to `..`
somewhere in the stack:

| Variant | Example | Defeats |
|---|---|---|
| Plain | `../../etc/passwd` | naive `str_replace` |
| Collapsing | `....//etc/passwd`, `....\/etc/passwd` | single-pass `str_replace('..','')` leaves `..` |
| URL-encoded | `%2e%2e%2f`, `..%2f`, `%2e%2e/` | check happens before PSR-7 decode |
| Double URL-encoded | `%252e%252e%252f` | one decode leaves `%2e%2e%2f` for the next layer |
| Overlong UTF-8 | `%c0%ae%c0%ae`, `%e0%80%ae` | older mod_rewrite/IIS |
| Unicode fullwidth | `．．／` (`．．／`) | NFKC normalization upstream |
| Null byte (legacy) | `..%00.jpg` | PHP < 8 truncates; PHP 8 `ValueError` for FS, but string compare still bites |
| Backslashes (Win) | `..\..\config.php` | `dirname()`/`realpath()` accept both on Windows |
| Windows ADS | `index.php::$DATA` | exposes source |
| Short names (Win) | `PROGRA~1`, `CONFIG~1.PHP` | literal-name allowlist |
| UNC (Win) | `\\server\share\x` | `realpath()` resolves |
| Unicode NFC/NFD | `café` vs `café` | allowlist on NFC, FS stores NFD |
| Case (Win/macOS) | `CONFIG.php` | case-sensitive allowlist |
| Trailing dot/space (Win) | `secret. ` resolves to `secret` | extension check |
| Absolute path | `/etc/passwd`, `C:\Windows\...` | concat `$base.'/'.$x` |
| Stream wrappers | `phar://`, `php://filter`, `zip://`, `data://` | passed to `file_get_contents`/`include` |

### 13.3 PHP-specific quirks

- **`realpath()` follows symlinks** and resolves to target. On shared hosting an attacker who can write a symlink in your storage dir pivots. Mitigate by `disable_functions=symlink` or `lstat`-checking each segment.
- **`realpath()` returns `false` for nonexistent paths.** Can't use it directly for write operations — resolve `dirname($candidate)` instead.
- **`pathinfo()` does NOT normalize `..`** — `pathinfo('../x.txt')['basename']` is `x.txt` but the dirname leak remains.
- **`basename()` strips `\` only on Windows.** On Linux, `basename('a\b')` returns the whole string. Don't rely on it cross-platform.
- **`parse_url()` treats `\\` inconsistently.** `parse_url('file:///etc/passwd')` returns a path, allowing scheme smuggling if you pass user input to `file_get_contents`.
- **TOCTOU**: `file_exists()` → `unlink()` is racy. A symlink swap between calls deletes the target. Use `@unlink()` with post-hoc verification, or open + `fstat`.
- **`open_basedir`** is defense-in-depth, not primary control. Bypassable via several PHP CVEs and disabled in many hosting environments.
- **PHP 8.0+ rejects null bytes** in filesystem functions with `ValueError`, but string-based path joins still propagate them — sanitize before comparison.

### 13.4 The canonical correct pattern (READ)

```php
use Flarum\Foundation\Paths;
use Flarum\Foundation\KnownError\RouteNotFoundException;

public function serve(string $relative, Paths $paths): string
{
    $base = realpath($paths->storage . '/myext');
    if ($base === false) {
        throw new \RuntimeException('Storage dir missing'); // (1)
    }

    if (str_contains($relative, "\0") || str_contains($relative, '://')) {
        throw new RouteNotFoundException();                 // (2) null byte + stream wrapper
    }

    $candidate = $base . DIRECTORY_SEPARATOR . ltrim($relative, '/\\'); // (3) ltrim defeats absolute paths
    $resolved  = realpath($candidate);                                  // (4) canonicalize
    if ($resolved === false) {
        throw new RouteNotFoundException();                              // (5) nonexistent → 404, don't leak
    }

    $baseWithSep = $base . DIRECTORY_SEPARATOR;
    if (! str_starts_with($resolved . DIRECTORY_SEPARATOR, $baseWithSep)) {
        throw new RouteNotFoundException();                              // (6) prefix-collision trap
    }

    return $resolved;
}
```

Walk-through of each line:

(1) **Fail closed** if base is missing. Never let `false . '/' . $x` produce a path rooted at `/`.
(2) **Reject null bytes and stream wrappers** before any FS call. `phar://`, `php://filter`, `zip://`, `data://` all bypass directory checks.
(3) **`ltrim($relative, '/\\')`** prevents an absolute `$relative` from rebasing the join. Without it, `'/etc/passwd'` would produce `$base . '//etc/passwd'` → resolves to `/etc/passwd`.
(4) **`realpath`** collapses `..`, decodes symlinks, normalizes separators (`\` → `/` on Linux behavior is consistent post-resolution).
(5) **Nonexistent → 404**. Don't differentiate "not found" from "denied" — leaks file existence.
(6) **The prefix-collision trap**: without the trailing separator, `/srv/flarum-storage` erroneously matches `/srv/flarum-storage-backup/secret`. Append `DIRECTORY_SEPARATOR` to both sides to force a directory boundary.

### 13.5 The canonical correct pattern (WRITE — file may not exist yet)

`realpath()` returns `false` for nonexistent files. For writes, resolve the **parent**
directory and combine with a strictly-validated filename:

```php
public function store(string $filename, string $contents, Paths $paths): void
{
    // Strict allowlist — see §13.6 for the full regex
    if (! preg_match('/\A(?!\.)[A-Za-z0-9._-]{1,200}\z/', $filename)) {
        throw new \InvalidArgumentException('Invalid filename');
    }
    if (preg_match('/\A(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|\z)/i', $filename)) {
        throw new \InvalidArgumentException('Reserved filename');
    }
    if (str_ends_with($filename, '.') || str_ends_with($filename, ' ')) {
        throw new \InvalidArgumentException('Invalid filename suffix');
    }

    $base = realpath($paths->storage . '/myext');
    if ($base === false) throw new \RuntimeException('Storage dir missing');

    $target = $base . DIRECTORY_SEPARATOR . $filename;
    if (! str_starts_with($target . DIRECTORY_SEPARATOR, $base . DIRECTORY_SEPARATOR)) {
        throw new \RuntimeException('Path escapes base');
    }

    file_put_contents($target, $contents, LOCK_EX);
    @chmod($target, 0640);
}
```

For nested subdirs: `realpath(dirname($candidate))` first, then verify the resolved
parent is inside `$base`, then concatenate the filename.

### 13.6 Filename allowlist regex (Windows-aware)

```php
// Anchored with \A/\z (NOT ^/$ — newlines bypass), length-bounded,
// rejects leading dot (.htaccess, ..), rejects trailing dot/space (Windows quirk).
if (! preg_match('/\A(?!\.)[A-Za-z0-9._-]{1,200}\z/', $filename)) reject();

// Reject Windows-reserved names (case-insensitive)
if (preg_match('/\A(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|\z)/i', $filename)) reject();

// Reject trailing dot/space (Windows strips them, exposing different file)
if (str_ends_with($filename, '.') || str_ends_with($filename, ' ')) reject();
```

`\A`/`\z` (not `^`/`$`) prevent newline-anchor bypasses. The negative lookahead `(?!\.)`
blocks `.htaccess` and `..`.

### 13.7 Flarum-specific safe primitives

- **`Flarum\Foundation\Paths`** exposes `$paths->base`, `->public`, `->storage`, `->vendor` — all `rtrim`med of separators. **Always start from one of these**; never accept a base directory from request input or settings.
- **`Flarum\Filesystem\FilesystemManager`** extends Laravel's. `disk('flarum-avatars')` returns a Cloud filesystem rooted at the disk's configured root. League\Flysystem's local driver **does prefix-confine** — `$disk->get('../../etc/passwd')` rejects with `PathTraversalDetected`. **Caveat**: protection is only on the Flysystem path. Don't extract `$disk->path($x)` and operate on it yourself — call methods on the disk (`get`, `put`, `delete`, `exists`).
- **`$disk->path($relative)`** (local driver only) returns the absolute path. **Treat the result as tainted** if `$relative` came from a user.
- Register custom disks via `Extend\Filesystem` so you inherit the manager's resolution.
- The disk abstraction also handles the `/` vs `\` separator issue that bites raw `realpath` callers cross-platform.

### 13.8 GDPR / data export endpoints (high-risk surface)

Export endpoints generate a ZIP from a user-supplied key (often `user_id` + token) then
stream it back. The official `flarum/gdpr` `ExportController` relies on the random
filename being unguessable, BUT it does **not** check the actor —
[vendor/flarum/gdpr/src/Http/Controller/ExportController.php:29](../../vendor/flarum/gdpr/src/Http/Controller/ExportController.php#L29).
This is a **capability URL** model: the email containing the filename is the
authorization. If your design copies this pattern, you accept that anyone with the URL
can download. For stricter auth, mirror `ConfirmErasureController` which DOES verify
actor identity —
[vendor/flarum/gdpr/src/Http/Controller/ConfirmErasureController.php:44](../../vendor/flarum/gdpr/src/Http/Controller/ConfirmErasureController.php#L44).

Safe pattern when building the archive:

```php
$archive = Str::random(40) . '.zip';                    // server-derived name
$path    = $paths->storage . '/myext-exports/' . $archive;  // no user input
$zip = new \ZipArchive();
$zip->open($path, \ZipArchive::CREATE | \ZipArchive::OVERWRITE);
foreach ($files as $f) {
    // Zip-slip: archive entry MUST be a constant or server-derived basename
    // — NEVER `$f->getClientFilename()` (extraction outside dir).
    $zip->addFile($f->getRealPath(), basename($f->path));
}
$zip->close();
```

### 13.9 Test cases the extension author MUST write

```php
/** @dataProvider traversalPayloads */
public function test_guard_rejects(string $payload): void {
    $this->expectException(RouteNotFoundException::class);
    $this->controller->serve($payload);
}
public static function traversalPayloads(): array {
    return [
        ['../etc/passwd'], ['....//etc/passwd'], ['..\\..\\boot.ini'],
        ['%2e%2e/etc/passwd'], ['%252e%252e%252fetc%252fpasswd'],
        ['..%c0%afetc/passwd'], ['/etc/passwd'],
        ['C:\\Windows\\System32\\config\\sam'],
        ["../../etc/passwd\0.jpg"], [''], ['.'], ['...'], ['..'],
        ['file.txt::$DATA'], ['PROGRA~1'], ['\\\\server\\share\\x'],
        ['php://filter/convert.base64-encode/resource=config.php'],
        ['phar:///tmp/x.phar'], ['CON'], ['secret. '], ['.htaccess'],
    ];
}
```

If you don't have a test suite, **at minimum** mentally walk each payload through your
guard. If any one would return a path instead of throwing, your guard is broken.

### 13.10 Anti-patterns — what NOT to do

| Anti-pattern | Why it fails |
|---|---|
| `str_replace('..', '', $p)` | `....//` collapses to `../` after replacement |
| `if (strpos($p, '..') === false)` | defeated by `%2e%2e` (URL-encoded) |
| `basename($_GET['file'])` | strips dirs only; legitimate-looking output (`passwd`) can still target wrong file if you `include "$dir/$result"` |
| `urldecode($p)` once and check | double-encoded variants survive |
| `preg_match('/\.\./',$p)` without `\A...\z` and decoding | only matches the literal sequence in current encoding |
| Using `dirname()` to "go up" then concat | moves the base, doesn't validate it |
| Trusting `$_SERVER['DOCUMENT_ROOT']` as base | user-settable under fastcgi |
| Logging the rejected path verbatim | log a hash; raw value can poison log viewers |

### 13.11 `Content-Disposition` filename sanitization

When streaming downloads, the `filename=` parameter is reflected to the user agent —
attack surface for XSS, response splitting, social-engineering names. **Never echo the
request filename**; derive it server-side:

```php
$safe = preg_replace('/[^A-Za-z0-9._-]/', '_', $record->original_name) ?: 'download';
return new Response\TextResponse($body, 200, [
    'Content-Type' => 'application/octet-stream',
    // Both filename (ASCII fallback) and filename* (RFC 5987 UTF-8)
    'Content-Disposition' => sprintf(
        'attachment; filename="%s"; filename*=UTF-8\'\'%s',
        $safe, rawurlencode($record->original_name)
    ),
]);
```

Strip CR/LF (`\r\n`) defensively even if your HTTP layer claims to handle it.

### 13.12 Quick checklist

- [ ] Base directory always sourced from `Flarum\Foundation\Paths`, never from input.
- [ ] Null byte and stream-wrapper (`://`) rejection before any FS call.
- [ ] `ltrim($relative, '/\\')` to neutralize absolute-path inputs.
- [ ] `realpath` + `str_starts_with($resolved.SEP, $base.SEP)` — the trailing separator is mandatory.
- [ ] Filename allowlist regex with `\A.../\z` anchors, NFC-aware, length-bounded, Windows-reserved-name rejection.
- [ ] For writes: resolve the PARENT with realpath, then concatenate the validated filename.
- [ ] Symlink check (`is_link($candidate)` before realpath) if your environment allows user-writable directories.
- [ ] Zip-slip: archive entry names are server-derived, never client-supplied.
- [ ] Downloads use a server-derived `Content-Disposition filename=` with stripped CR/LF.
- [ ] Tests exist for at least 10 of the §13.9 payloads.

---

## §14. SSRF — server-side fetch & client-side fetch

### Server-side (`Http\Client`, `Guzzle`, `curl_init`, `file_get_contents`)

```bash
rg -n "Http\\\\Client|GuzzleHttp\\\\Client|curl_init|file_get_contents\\(" src/
```

- URL fetched from user input MUST validate scheme AND resolved host:
  - Reject internal IPs: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16` (AWS metadata), `0.0.0.0/8`.
  - Reject IPv6 link-local (`fe80::/10`), unique-local (`fc00::/7`), loopback (`::1/128`).
  - Resolve DNS → IP, re-check the IP. Defeat DNS rebinding by pinning the resolved IP for the actual request.
- Disable `allow_url_fopen` if you pass user URLs to image libraries. Intervention\Image
  `make($url)` is a known SSRF vector (CVE-2023-40033 in Flarum core).

### Client-side (`fetch()` in browser)

Browser-fetch of user-controlled URLs is **not full SSRF** (no server credentials leak,
CORS gates cross-origin reads) but still lets attackers:
- Send the victim's browser to GET a URL they chose (cookie-less for cross-origin, but the request happens — exploits IP-based location tracking, internal forum URLs, etc.).
- Trigger `javascript:` / `data:` URLs if scheme is unchecked.

Reference: [renderLottie.js:14-23](js/src/common/utils/renderLottie.js#L14-L23) —
same-origin check + streamed size cap.

```js
let parsed;
try { parsed = new URL(url, location.origin); }
catch { throw new Error('Invalid URL'); }
if (parsed.origin !== location.origin) throw new Error('Must be same-origin');
const response = await fetch(parsed.href);
```

For multi-MB binary fetches, ALSO implement a streamed size cap. Never buffer the whole
response with `response.arrayBuffer()` / `response.json()` without enforcement.

---

## §15. Open redirect (`?return=`, `redirect`, `next`)

CVE-2024-21641 hit Flarum core. Pattern to avoid:

```php
// BAD
return new RedirectResponse($request->getQueryParams()['return'] ?? '/');
```

### Correct shape

```php
$return = (string) ($request->getQueryParams()['return'] ?? '/');
$base   = $this->url->to('forum')->base();

// Allow only relative paths starting with /, or absolute URLs whose host matches forum host
if (! str_starts_with($return, '/') || str_starts_with($return, '//')) {
    $return = '/';
} else {
    // Reject protocol-relative `//attacker.com` and explicit absolute URLs.
    $parsed = parse_url($return);
    if (isset($parsed['host']) && $parsed['host'] !== parse_url($base, PHP_URL_HOST)) {
        $return = '/';
    }
}
return new RedirectResponse($base . $return);
```

---

## §16. CSRF & the API-token bypass trap

Built-in: `Flarum\Http\Middleware\CheckCsrfToken` requires `csrfToken` body field OR
`X-CSRF-Token` header on every non-GET/HEAD/OPTIONS API route. `hash_equals` against
session token.

### Critical gotcha

`AuthenticateWithHeader` (the API-token authentication middleware) sets
`bypassCsrfToken = true` AND `bypassThrottling = true` on every request bearing a valid
`Authorization: Token <key>` header. **Token-authenticated requests skip CSRF entirely
and have zero rate limiting.**

For your extension: when a controller is reached via token auth, you cannot assume CSRF
was checked. Only the token's authenticity was verified. Don't add features that combine
"sensitive state-change" with "no in-request actor verification" assuming CSRF as a
backstop.

### Red flags

```bash
rg -n "bypassCsrfToken|bypassThrottling" src/
rg -n "Extend\\\\Csrf|exemptRoute" src/
```

- Controller setting `$request = $request->withAttribute('bypassCsrfToken', true)` outside of explicit token-auth.
- `Extend\Csrf()->exemptRoute(...)` on a mutation route — only acceptable for webhook receivers WITH HMAC signature verification.
- Custom middleware that calls `$next($request)` before validating the body/headers.

---

## §17. ApiKey / AccessToken — the master-key footgun

**This is the most dangerous section in this file. Read it fully.**

### The unbound ApiKey master-key problem

`ApiKey` has nullable `user_id`. The `AuthenticateWithHeader` middleware:
- If `ApiKey::user_id` is set → impersonate that user.
- If `ApiKey::user_id` is NULL → parse `;userId=N` from the `Authorization` header and **impersonate ANY user including admin (id=1)**.

The `allowed_ips` column on ApiKey **exists in the schema but the middleware never
checks it**. There is no scope enforcement on `scopes` either.

```
Authorization: Token <master-key>;userId=1     → admin
Authorization: Token <master-key>;userId=42    → user 42, any group
```

### Red flag

```bash
rg -n "ApiKey::|new ApiKey\\(|->createApiKey\\(" src/ migrations/
```

ANY extension code that creates an `ApiKey` with `user_id = NULL` is creating a
permanent master key. Footguns:
- "For our cron job" — use a session token bound to a real admin user instead.
- "For our webhooks" — use HMAC signature, not ApiKey.
- "For our admin tools" — bind the key to the admin user that created it.

### Correct shape

```php
// If you absolutely need an ApiKey for service-to-service auth:
$key = new ApiKey();
$key->key     = ApiKey::generate()->key;           // random
$key->user_id = $serviceAdminUserId;               // BOUND — not null
$key->save();
// Document inline why: who created it, what it's for, how to rotate.
```

For webhook ingestion: never use ApiKey. Use HMAC:
```php
$expected = hash_hmac('sha256', $rawBody, $sharedSecret);
$received = $request->getHeaderLine('X-Webhook-Signature');
if (! hash_equals($expected, $received)) throw new PermissionDeniedException();
```

### AccessToken subtypes

- `SessionAccessToken` — 1h, used in browser sessions, scoped to the actor.
- `DeveloperAccessToken` — 0 = NEVER expires. Used for personal API tokens. Full user permissions.
- `RememberAccessToken` — used in "remember me" cookies.
- All grant **full user permissions** — there are no per-token scopes implemented in core.

If your extension creates DeveloperAccessTokens programmatically, document the threat
model and offer a UI to revoke them.

---

## §18. Throttling / rate limiting (and how to break it)

`Api\Middleware\ThrottleApi` iterates registered throttler callables. **Any throttler
returning `false` short-circuits and exempts the request from ALL other throttlers.**

```php
// BAD — exempting admins from login throttle ALSO exempts them from a different throttler that detects credential stuffing
(new Extend\ThrottleApi())->set('exemptAdmins', function ($request) {
    $actor = RequestUtil::getActor($request);
    if ($actor->isAdmin()) return false;       // ← KILLS every other throttler too
});

// GOOD — return null to abstain
(new Extend\ThrottleApi())->set('exemptAdmins', function ($request) {
    $actor = RequestUtil::getActor($request);
    if ($actor->isAdmin()) return null;        // ← just opts out of THIS throttler
    return $myThrottleDecision;
});
```

Return semantics:
- `false` → **bypass ALL throttlers** (exempt entire request).
- `true` → throttle (limit hit).
- `null` → abstain (let other throttlers decide).
- An integer → seconds remaining until reset.

Also note: token-authenticated requests have `bypassThrottling=true` set
automatically (§16). Your throttler is NEVER consulted for those.

---

## §19. Notifications (data column leakage)

`NotificationResource::content` exposes the raw `data` column verbatim. Whatever you
put in there is JSON-serialized to every recipient — no policy re-check, no visibility
filter, no sanitization.

### Red flags

- Storing user-controlled excerpts (post body fragments, usernames, file names) in `data`.
- Putting subject content in `data` thinking "the subject relation will gate it" — the subject relation IS gated, but `data` is independent.
- Notification cache: if a subject becomes private/hidden after the notification was sent, the cached `data` still leaks the original content.

### Correct shape (Blueprint)

```php
public function getData()
{
    return [
        // Store only IDs and safe scalars
        'postId'        => (int) $this->post->id,
        'discussionId'  => (int) $this->post->discussion_id,
        // NEVER:
        // 'postExcerpt' => $this->post->content,    ← leaks even if subject becomes private
    ];
}
```

Rehydrate at render time via the `subject` relation, which IS visibility-checked.

### Recipient gating

Re-check `can('view', $subject)` for each recipient before `NotificationSyncer::sync()`:

```php
$recipients = $allUsers->filter(fn($u) => $u->can('view', $discussion));
$this->notifications->sync($blueprint, $recipients);
```

CVE-2023-22488 hit Flarum core via this exact pattern — alert-stage visibility was not
re-checked for email channel.

---

## §20. Events, console schedules, queued jobs (actor identity)

### Event listeners (`Extend\Event::listen`)

Listeners run in undefined order in the global dispatcher. Any throwing listener aborts
the chain.

- Listener that mutates a different resource than the event source: re-run `assertCan` on the mutated resource. The originating event's permission check doesn't carry over.
- Listener that calls a Service Bus command: pass the actor explicitly. Don't trust an inferred actor in the queue worker context.

### Console schedules (`Extend\Console::schedule`)

Scheduled callbacks run with NO actor. The container resolves them as if invoked by
nobody → effectively Guest.

```php
// BAD — runs as Guest, $discussion->hide() will be denied silently
(new Extend\Console())->schedule('myext:cleanup', function () {
    Discussion::where('hidden_at', '<', now()->subDays(30))->each->hide();
});

// GOOD — instantiate an admin actor explicitly
(new Extend\Console())->schedule('myext:cleanup', function () {
    $admin = User::where('id', 1)->first();
    Discussion::where('hidden_at', '<', now()->subDays(30))
        ->each(fn($d) => $d->hide($admin));
});
```

### Queued jobs

Jobs serialized to the queue lose request context. Pass `actorId` as a property; rehydrate
the User in `handle()` and use `assertCan` on every operation.

---

## §21. Settings — `serializeToForum` has NO visibility callback

`Extend\Settings::serializeToForum(jsName, settingKey, cast, default)` exposes the
setting to **every client request**, including unauthenticated guests. There is no
per-actor visibility filter.

```bash
rg -n "serializeToForum\\(" extend.php src/
```

### Red flags

- Exposing any secret via `serializeToForum`: API keys, integration tokens, webhook URLs containing tokens, raw email addresses, internal IPs, license keys.
- Exposing HTML/admin-controlled raw strings without a sanitizer cast.

### Correct shape

```php
(new Extend\Settings())
    // Public booleans: fine
    ->serializeToForum('myextHoverPlay', 'myext.hover-play', 'boolval', false)

    // HTML from admin: pass through a sanitizer cast
    ->serializeToForum('myextHeader', 'myext.header_html',
        fn(string $html) => app(\Vendor\MyExt\Support\HtmlSanitizer::class)->clean($html),
        '')

    // Secrets: NEVER serializeToForum. Read in your authorized controller only.
```

### `Settings::default()` is immutable across extensions

If two extensions register `->default('myext.foo', ...)` Flarum throws on boot. Always
prefix settings with your extension id and never `default()` a third-party extension's
key.

### Settings UI exposure

The admin settings panel shows ALL `settings` rows to admins. If you store a secret in
the `settings` table (not exposed via `serializeToForum`), it's still visible to admins.
For per-user secrets, use a dedicated table with policy-gated access.

---

## §22. Translator interpolation & locale conventions

### Frontend behavior

`app.translator.trans('key', {name: user.displayName()})` returns Mithril children;
`{name}` becomes a text node. **Safe by default.** Tags inside locale strings
(`<strong>`, `<em>`) become Mithril elements; attributes like `href` are stripped.

### The XSS path

```ts
// CVE-2021-32671 pattern
m.trust(app.translator.trans('key', { name: user.displayName() }, true));
// ↑ extract:true flattens vnodes to string, then m.trust parses as HTML.
// Username containing <img onerror=...> → XSS.
```

Rule: **never `m.trust(translator.trans(...))`** with user-substituted vars. If you
need raw HTML, build the vnode tree manually.

### Backend `app('translator')->trans()`

Backend uses Symfony Translator (no extract flag). The output is a string. If you pass
that string into:
- An email template's `{!! !!}` → XSS in email.
- A formatter token / s9e configurator → potentially renders as HTML.

Always escape with `e()` / `htmlspecialchars` before injecting translated strings into
any HTML context unless you control the whole locale string.

### Locale conventions

- `locale/en.yml` mandatory. Add `locale/pt-BR.yml` if you maintain a Portuguese fork.
- Single top-level key matching the extension slug: e.g. `flarum-tags:`, `flarum-likes:`, `myext:`.
- Custom permission strings under `<slug>.group_permission.<ability_snake>` so the admin UI labels them.

### Settings key conventions (consistency check)

Official Flarum extensions use the pattern `<vendor>-<ext>.<snake_case_key>`:

| Extension | Example key |
|---|---|
| flarum/tags | `flarum-tags.default_tag` |
| flarum/gdpr | `flarum-gdpr.allow-anonymization` |
| flarum/nicknames | `flarum-nicknames.min` |
| flarum/likes | `flarum-likes....` |

Pick **one** style per extension; never mix kebab and snake within a single extension's
settings namespace. Reference:
[vendor/flarum/gdpr/extend.php:60](../../vendor/flarum/gdpr/extend.php#L60).

### Cast functions matter

- `'boolval'` for booleans (otherwise `'0'`/`'1'` strings surface in JS).
- `'intval'` for integers.
- `null` (no cast) only when the value is already a serialized JSON / opaque string.
- Raw HTML strings: write a sanitizer cast — never `null`.

---

## §23. Logging sensitive data

Flarum writes to `storage/logs/flarum.log` via `RotatingFileHandler`. **No automatic
redaction.**

### Red flags

```bash
rg -n "resolve\\('log'\\)|app\\('log'\\)|Log::" src/
rg -n "->info\\(|->warning\\(|->error\\(.*\\\$request" src/
```

- `app('log')->info('payload', $request->getParsedBody())` — dumps `password`, `email`, `token` fields.
- Logging full `$request` / `$body` / `$headers` — includes `Authorization` header.
- Stack traces from exceptions that originated in HTTP layer — may include POST body.

### Correct shape

```php
// Strip sensitive keys before logging
$safe = Arr::except($request->getParsedBody() ?? [], [
    'password', 'password_confirmation', 'remember', 'token',
    'csrfToken', 'email', 'apiKey',
]);
app('log')->info('myext upload', ['actor' => $actor->id, 'fields' => array_keys($safe)]);

// For exceptions: log only what you control
app('log')->error('myext failure', [
    'actor' => $actor->id,
    'class' => get_class($exception),
    'msg'   => $exception->getMessage(),    // verify the message doesn't include user data
]);
```

Match `LogReporter` — it only logs `Throwable`, not arbitrary arrays.

---

## §24. Cache keys (cross-actor cache poisoning)

`Cache::remember('key', $ttl, fn() => …)` returns the cached value for `'key'`
regardless of who's asking. If the computation depends on the actor's permissions,
include the actor in the key.

### Red flags

```bash
rg -n "Cache::remember|->remember\\(|cache\\(\\)->remember" src/
```

- Cache key like `'discussion.'.$id` for a value that varies by actor.
- Cache that captures included-relation visibility (per-actor) keyed by URL only.

### Correct shape

```php
$key = sprintf(
    'myext.user.%s.notifications',
    $actor->isGuest() ? 'guest' : (int) $actor->id
);
$payload = Cache::remember($key, 60, fn() => $this->compute($actor));

// For permission-bucket caching (admins see one view, members another):
$bucket = $actor->isAdmin() ? 'admin' : ($actor->isGuest() ? 'guest' : 'member');
$key = "myext.list.$bucket";
```

Reference: core uses `"user.{$actor->id}.new_notification_count"` —
[NotificationResource.php:87](../../vendor/flarum/core/src/Api/Resource/NotificationResource.php#L87).

---

## §25. Validators

For non-trivial input validation, prefer `Flarum\Foundation\AbstractValidator` over
inline checks. Integrates with Laravel `ValidationException` and surfaces field-level
errors to the JSON:API client.

```php
class MyValidator extends AbstractValidator
{
    protected $rules = [
        'title'  => ['required', 'string', 'max:100'],
        'slug'   => ['required', 'string', 'max:100', 'regex:/^[A-Za-z0-9:_\-]+$/'],
        'reason' => ['nullable', 'string', 'max:1000'],
    ];
}
// extend.php
(new Extend\Validator(MyValidator::class))->configure(fn($v, $data) => …);

// Controller
$validator->assertValid($attributes);                          // throws ValidationException on failure
```

**Flarum v2 prefers schema-level validation**: official extensions chain rules directly
onto `Schema\*` fields rather than declaring `AbstractValidator` subclasses. Reference:
`flarum/nicknames` chains `->rule('not_regex:/[\[\]()<>]/')->regex(...)->minLength(...)->unique(...)`
on a single `Schema\Str::make('nickname')` —
[vendor/flarum/nicknames/src/Api/UserResourceFields.php:36](../../vendor/flarum/nicknames/src/Api/UserResourceFields.php#L36).

### Red flags

- Validator declared but never invoked.
- `'sometimes'` rule on security-critical fields (e.g. `user_id`, `status`).
- Inline `preg_match` checks scattered across controllers — consolidate at the schema layer.

---

## §26. Migrations

```php
<?php
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Schema\Builder;

return [
    'up' => function (Builder $schema) {
        if ($schema->hasTable('myext_items')) return;          // idempotency

        $schema->create('myext_items', function (Blueprint $table) {
            $table->id();
            $table->string('title', 100);
            $table->string('slug', 100)->unique();
            $table->unsignedInteger('post_id');
            $table->unsignedInteger('user_id')->nullable();
            $table->timestamps();

            $table->foreign('post_id')                          // FK with cascade
                  ->references('id')->on('posts')
                  ->cascadeOnDelete();
            $table->foreign('user_id')
                  ->references('id')->on('users')
                  ->onDelete('set null');
            $table->index(['slug']);
        });
    },
    'down' => function (Builder $schema) {
        $schema->dropIfExists('myext_items');
    },
];
```

Reference: `flarum/tags` pivot table with `cascadeOnDelete()` + composite primary key —
[vendor/flarum/tags/migrations/2023_03_01_000000_create_post_mentions_tag_table.php:36](../../vendor/flarum/tags/migrations/2023_03_01_000000_create_post_mentions_tag_table.php#L36).

**Pre-FK orphan cleanup** for dirty installs (so the migration doesn't crash on stale
production rows): mirror `flarum/flags` —
[vendor/flarum/flags/migrations/2018_06_27_101600_change_flags_add_foreign_keys.php:17](../../vendor/flarum/flags/migrations/2018_06_27_101600_change_flags_add_foreign_keys.php#L17).

### Red flags

- Migration that drops a column WITHOUT a parallel down. Future-you cannot roll back.
- `up` that assumes the table doesn't exist (no `hasTable` check) — fails on re-runs.
- Settings removal that only edits `extend.php` without deleting persisted DB rows.

### Removing persisted settings (cleanup migration pattern)

```php
use Illuminate\Database\ConnectionInterface;

return [
    'up' => function (ConnectionInterface $db) {
        $db->table('settings')
            ->whereIn('key', [
                'myext.legacy_a',
                'myext.legacy_b',
            ])
            ->delete();
    },
    'down' => fn () => null,                                    // no rollback for cleanups
];
```

---

## §27. Frontend `extend()` / `override()` discipline

```ts
import { extend, override } from 'flarum/common/extend';
```

### Critical gotcha — `override()` swallows errors silently

`override(Component.prototype, 'view', fn)` wraps `fn` in try/catch. On throw, it
returns `undefined` and renders an empty vnode. **Silent broken UI.**

`extend(Component.prototype, 'view', fn)` also try/catches.

### Footguns

- `override` that throws on a specific code path → user sees blank where the component should be. Always test the unhappy paths.
- `extend(UserControls.prototype, 'view', items => items.add('ban', ...))` without permission guard — non-admins see the button (and clicking it just hits a 403, but the leak of "ban exists" is itself information disclosure to harassment cases).
- Module-level state holding actor data — leaks across SPA navigation if `app.session.user` changes (impersonation, login/logout).

### Correct shape

```ts
extend(UserControls.prototype, 'view', function (items) {
    const actor = app.session.user;
    const target = this.attrs.user;
    if (!actor?.attribute('canBan', target)) return;            // gate every UI addition
    items.add('myext-ban', <Button onclick={() => this.banUser()}>Ban</Button>, 100);
});
```

For data that varies by actor, ALWAYS read `app.session.user` per render — never at
module scope.

---

## §28. `app.session.user`, `app.forum.attribute('headerHtml')` traps

### `app.session.user` null safety

```ts
app.session.user           // User | null   — null for guests
app.session.user.isAdmin() // ❌ throws on guests
app.session.user?.isAdmin() // ✅ optional chaining → undefined → falsy
```

`isAdmin` attribute is only set when the actor reads its OWN UserResource —
fetching another user does NOT give you that user's admin status. Use
`user.attribute('canBeAssignedAdmin')` patterns or server-side checks for cross-user
admin status.

### `app.forum.attribute(...)` — admin-controlled raw HTML

Core exposes these unconditionally:
- `headerHtml`, `footerHtml`, `welcomeMessage` — raw HTML pasted by admin.
- `customCss` — admin-pasted CSS.
- `logoUrl`, `faviconUrl` — admin-controlled URLs.

Server-side rendering inlines them raw via `{!! !!}` in the forum.blade.php; client-side
`WelcomeHero` uses `m.trust(app.forum.attribute('welcomeMessage'))`.

**This is by design** — admins can paste arbitrary HTML. But:
- If your extension allows non-admin actors to write to these → stored XSS.
- If your extension surfaces these to non-admin editors (e.g. "customize your subforum header") → stored XSS.
- Don't add similar `*Html`/`*Css` attributes to your own settings without scoping them to admin-only edit AND sanitizing on write.

### Custom `forum.attribute` extension

Adding attributes via `Extend\ForumResource`/etc. — they are also unconditional. Per-actor
visibility is not supported on `forum.attribute()`. If a value should vary per actor,
expose it on UserResource instead.

---

## §29. Real-time / WebSocket broadcast leaks

If `flarum/realtime` is installed and you broadcast events via `Extend\Realtime`:

```php
// BAD — no recipient routing, broadcasts to channel 'public'
(new Realtime())->broadcastModelEvent(
    [PrivateMessageSent::class],
    fn($event) => $event->message
);

// GOOD — Generator yields per-user channels
(new Realtime())->broadcastModelEvent(
    [PrivateMessageSent::class],
    function ($event) {
        foreach ($event->message->recipients as $user) {
            yield ['channel' => "private-user={$user->id}", 'payload' => [
                'messageId' => $event->message->id,           // ID only, not body
            ]];
        }
    }
);
```

The frontend rehydrates the message via authorized API call — never broadcast the
content itself.

### Red flags

- Broadcasting a model that has `user_id` / per-user visibility to channel `'public'`.
- Broadcasting the full model payload — broadcast IDs only, rehydrate via API.

---

## §30. Sessions, cookies, headers, GDPR

### Cookies

`CookieFactory` defaults:
- `secure` only if request is HTTPS (`isSecure()` returns true).
- `SameSite=Lax`.
- `HttpOnly` forced.

**Behind a reverse proxy without `Trusted Proxies` configuration**, Flarum sees
`scheme=http` even though clients are on HTTPS → cookies not flagged Secure. Set
`cookie.secure = true` in `config.php` when TLS terminates at the LB.

CVE-2025-27794: session not rotated on auth boundary. Flarum core was patched. For your
own auth flows (e.g. SSO callback), always call `$session->migrate(true)` on login.

### Security headers

Core only adds `X-Content-Type-Options: nosniff`. **No default CSP, no X-Frame-Options,
no Referrer-Policy.** If your extension hosts sensitive admin UI or processes
user-uploaded content, register a middleware:

```php
class SecurityHeadersMiddleware implements MiddlewareInterface
{
    public function process(ServerRequestInterface $req, RequestHandlerInterface $h): ResponseInterface
    {
        $resp = $h->handle($req);
        return $resp
            ->withHeader('X-Frame-Options', 'SAMEORIGIN')
            ->withHeader('Referrer-Policy', 'strict-origin-when-cross-origin')
            ->withHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    }
}
// extend.php
(new Extend\Middleware('forum'))->add(SecurityHeadersMiddleware::class);
```

### GDPR / data export integration

If `flarum/gdpr` is installed and your extension stores PII (user-controlled data
beyond the standard profile fields), register a UserData type:

```php
(new \Flarum\Gdpr\Extend\UserData())
    ->addType(MyExtensionUserData::class);
```

`MyExtensionUserData::piiFields()` must return the list of stored PII columns. Missing
registration = incomplete data export = user can't access their own data (GDPR right of
access violation).

Don't over-disclose: never include moderator-only notes ABOUT the user in their data
export — those belong to the moderator, not the user.

---

## §31. Dead-code & refactor heuristics

### Finding dead code

```bash
# Functions exported but cited only in comments
rg -n "^export (default |function |const |class |interface )" js/src/
# For each name, count references outside the defining file

# Components never rendered
rg -l "export default class (\\w+)" js/src/ \
  | while read f; do
      name=$(rg -o "export default class (\\w+)" "$f" -r '$1' | head -1)
      echo -n "$name: "
      rg -c "<$name|app\\.modal\\.show\\($name|new $name" js/src/ | wc -l
    done

# Distinguish doc comments from dead code
rg -n "^\\s*//\\s*(if|for|while|return|const|let|var|function|class|public|private|protected|\\{|\\}|\\$|app\\.|this\\.)" js/src/
```

### Heuristic — "is this dead?"

Before deleting:
1. `rg -n "<name>" .` ignoring `dist/` and `node_modules/`.
2. Check string references (`'<name>'`, `"<name>"`) — may be a dynamic registry lookup.
3. Check `locale/*.yml` and templates — consumed by string key.
4. Check comments.

If all four return empty, delete is safe.

### Refactor order (safest first)

1. Unused interfaces/types.
2. Functions exported with no consumer.
3. Duplicate `oninit` defaults (class fields cover them).
4. Missing typings (add to remove `as unknown as`).
5. Legacy settings — LAST. Requires migration to delete persisted rows.

### What NOT to remove

- Comments explaining WHY (workaround, invariant, hidden constraint).
- "Looks like fallback" code that handles legacy production state (e.g. users marked
  before a new schema existed). Removing breaks real users.
- Constants/enums shared between frontend and backend. Linter may flag the JS half as
  unread; the PHP half writes it.
- `dist/` and `node_modules/`.

### Migration template for removing persisted settings

See §26.

---

## §32. Final pre-commit checklist

Run through this list **before** asking the user to review or merge. **No exceptions
for "small" changes.**

### Backend — authorization

- [ ] Every `Routes('api')->...(...)` lists a controller that calls `RequestUtil::getActor($request)->assertRegistered()` (or stricter) before any work.
- [ ] Every `Endpoint\*::make(...)` chains `->can(…)`, `->admin()`, or `->authenticated()`.
- [ ] Every actor-vs-resource ID comparison uses `===` after `(int)` cast on both sides.
- [ ] No `forceAllow` / `forceDeny` without an inline comment explaining the override.
- [ ] No permission seeded with `group_id = Group::GUEST_ID` beyond core defaults (`viewForum`, `signUp`).
- [ ] No policy decision based on a nullable FK (use the parent model's permission instead).

### Backend — data access

- [ ] Every `Discussion::find`/`Post::find`/`User::find` is preceded by `whereVisibleTo($actor)` OR happens inside a policy-gated path.
- [ ] Every `$discussion->posts`/`$user->groups` relation read uses `->whereVisibleTo($actor)` when actor-scoped.
- [ ] Every Schema field exposing PII / internal data has `->visible(fn(...))`.
- [ ] Every field with sensitive write semantics (`status`, `user_id`, `role`, `price`) has `->writable(fn(...) => admin || self)`.
- [ ] Resources for per-user data implement `scope(Builder, Context)` to restrict rows.
- [ ] No `->fill($body)`, `->forceFill(…)`, `Model::create($body)`, `protected $guarded = []`.
- [ ] Extending core resources (`UserResource` etc.) — every new field has explicit `->visible()`.

### Backend — injection

- [ ] No `whereRaw`/`orderByRaw`/`selectRaw`/`DB::raw` concatenating user input.
- [ ] Every `LIKE` on user input escapes `%` and `_`.
- [ ] `orderBy` uses an allowlist mapping for sort column names.
- [ ] Filter implementations use parameter binding, never string concat.
- [ ] No access to `$_GET` / `$_POST` / `$_REQUEST` directly.
- [ ] Translated strings passed to email `{!! !!}` or formatter tokens are escaped first.

### Backend — files & network

- [ ] Every upload validates: actor permission, size (null + cap), extension allowlist, MIME via `finfo_open`, server-generated filename, restrictive `chmod`.
- [ ] Image uploads re-encoded through Intervention\Image (or equivalent) — raw bytes not written to public disks.
- [ ] Every private file served sets `nosniff`, `X-Frame-Options`, `Cache-Control: private`, `CSP: sandbox` for PDFs.
- [ ] Path traversal blocked by `realpath` + prefix check + filename regex allowlist.
- [ ] Server-side URL fetches validate scheme AND resolved host (reject RFC1918, `169.254.169.254`, `::1`, `fe80::/10`, `fc00::/7`).
- [ ] No `?return=`/`redirect=` redirect to absolute URL without host check.

### Backend — auth & sessions

- [ ] No `withAttribute('bypassCsrfToken', true)` outside of explicit token-auth paths.
- [ ] No `ApiKey` with `user_id = NULL` created by extension code.
- [ ] Custom auth flows call `$session->migrate(true)` on login.
- [ ] No middleware calling `$next($request)` before validation completes.
- [ ] No webhook receiver using `ApiKey` — use HMAC instead.

### Backend — async & side effects

- [ ] Event listeners that mutate a different resource re-run `assertCan` on the mutation.
- [ ] Console schedules instantiate an explicit admin actor — they don't run as Guest by accident.
- [ ] Queued jobs serialize `actorId` and rehydrate the user with `assertCan` per operation.
- [ ] Throttler callbacks return `null` to abstain (not `false`, which exempts all throttlers).
- [ ] Notifications store IDs/safe scalars in `data`, never user-controlled content.
- [ ] Recipient lists filtered by `->can('view', $subject)` before `NotificationSyncer::sync()`.
- [ ] Realtime broadcasts route per-user channels for per-user data — never `'public'`.

### Backend — settings, logging, cache

- [ ] No secret value exposed via `serializeToForum(...)`.
- [ ] HTML/admin settings exposed via `serializeToForum` pass through a sanitizer cast.
- [ ] `Extend\Settings::default()` keys are prefixed with the extension id (no collisions).
- [ ] No `app('log')->info($request->getParsedBody())` — sensitive fields stripped first.
- [ ] Cache keys include `$actor->id` (or guest/admin/member bucket) when the cached value varies by actor.

### Frontend

- [ ] Every `m.trust(x)` traces back to a sanitized source (backend AND/OR JS mirror).
- [ ] No `m.trust(app.translator.trans(...))` with user-substituted vars.
- [ ] No `<a href={userInput}>` without a `^https?:` protocol check.
- [ ] No `innerHTML = userInput`.
- [ ] All `style: url(...)` values pass `safeCssUrl` (no `javascript:` / `data:` / `file:`).
- [ ] Every `extend(UserControls.prototype, 'view', …)` (or similar UI extension) gates additions by actor permission.
- [ ] No module-level state holding actor-specific data.
- [ ] Admin-only routes redirect non-admins in `oninit`.
- [ ] `app.session.user` accessed via `?.` optional chaining.
- [ ] Same-origin (or explicit allowlist) check on every `fetch(userUrl)` call.
- [ ] Streamed size cap on every `fetch` downloading multi-MB binary payloads.
- [ ] `tsc --noEmit` (TS projects) passes; `webpack --mode production` passes.
- [ ] `js/dist/{forum,admin}.js` regenerated and committed.

### Migration & cleanup

- [ ] Migration is idempotent (`hasTable`/`hasColumn` guards).
- [ ] Migration has a working `down` OR documents why rollback is impossible.
- [ ] If a setting/column was removed, the migration deletes its persisted rows.
- [ ] Locale entries added for every visible string AND every custom permission ability.
- [ ] No `// removed`/`// legacy` comments left on dead code.

### Build & lint

- [ ] `php -l <changed files>` passes.
- [ ] If JS changed: `npm run build` regenerated `js/dist/{forum,admin}.js` and they're committed.
- [ ] Smoke-test the feature manually before reporting done.

---

## §33. Severity calibration & quick triage

- 🔴 **High** — exploit possible by a **guest** or low-privileged user, OR a single request can OOM/DoS the host, OR PII leak across users. Patch immediately, hold the release.
- 🟠 **Medium** — requires a compromised admin OR an already-degraded server. Patch before the next release; document defense-in-depth gaps.
- 🟡 **Low** — narrow conditions, mitigated by other layers (browser-side SSRF with CORS in front, scheme allowlist + size cap, etc.). Add to backlog; address in next refactor.
- ⚪ **Informational** — design/documentation note. Discuss with product before changing.

### Quick "is this a vuln?" heuristic

For each finding, answer three questions:

1. **Who triggers it?** Guest > authenticated user > admin > internal infra. Further left = more severe.
2. **What do they gain?** Other-user data read > other-user write > RCE > DoS > PII leak.
3. **What does it require?** Default config (severe) > admin-already-compromised (defense-in-depth) > misconfigured server (low).

The triple gives the real severity — not "looks ugly".

### Known Flarum-class incidents to learn from

| ID | Class | One-liner |
|---|---|---|
| CVE-2023-22487 | IDOR | Included relation visibility not re-checked. |
| CVE-2023-22488 | Data leak | Notification recipient list not filtered by `can('view', $subject)`. |
| CVE-2023-22489 | AuthZ bypass | Policy gated on nullable FK; null short-circuited to allow. |
| CVE-2021-32671 | XSS | Translator `{name}` rendered via `m.trust(... , true)`. |
| CVE-2026-30913 | Email injection | Display-name autolinked in plain-text mail. |
| CVE-2026-41887 | LFI | LESS `@import` in admin-supplied theme variable. |
| CVE-2023-40033 | SSRF/LFI | Intervention\Image fetched URL from user-controlled string. |
| CVE-2024-21641 | Open redirect | `?return=` redirected to attacker-controlled URL. |
| CVE-2025-27794 | Session fixation | Session not rotated on auth boundary. |

If your change touches any class above, re-read the corresponding section before committing.

---

## §34. Patterns from official Flarum v2 extensions (canonical citations)

When in doubt about how to shape something, **read the official first-party extension
that does the closest thing** and copy its pattern. The pointers below cite the cleanest
example for each pattern type. Paths are relative to the workbench root (the repo
running this `CLAUDE.md`), pointing into `vendor/flarum/<ext>/...`.

### A. Authorization & policies

- **Policy `can()` shape** — return `allow()`, `deny()`, or `null` (abstain). Slugs follow `tag{id}.{ability}` for per-instance permissions.
  [vendor/flarum/tags/src/Access/TagPolicy.php:18](../../vendor/flarum/tags/src/Access/TagPolicy.php#L18)

- **Policy registration** — `modelPolicy()` + `globalPolicy()` side by side.
  [vendor/flarum/tags/extend.php:125](../../vendor/flarum/tags/extend.php#L125)

- **Seed custom abilities to `MEMBER_ID`, never `GUEST_ID`.**
  [vendor/flarum/likes/migrations/2015_09_04_000000_add_default_like_permissions.php:13](../../vendor/flarum/likes/migrations/2015_09_04_000000_add_default_like_permissions.php#L13)

- **Per-resource `assertCan` inside a command handler before mutation.**
  [vendor/flarum/flags/src/Command/DeleteFlagsHandler.php:30](../../vendor/flarum/flags/src/Command/DeleteFlagsHandler.php#L30)

### B. Visibility scoping

- **`ScopeVisibility` registration** via `Extend\ModelVisibility`.
  [vendor/flarum/tags/extend.php:133](../../vendor/flarum/tags/extend.php#L133)

- **Eager-loaded relation wrapped in `whereVisibleTo`** to plug the default-relation bypass.
  [vendor/flarum/tags/extend.php:74](../../vendor/flarum/tags/extend.php#L74)

- **Custom scoper with double `whereNotIn`** — the permission must hold for ALL of a discussion's tags, not just one. Single-`whereIn` is a vuln.
  [vendor/flarum/tags/src/Access/ScopeDiscussionVisibilityForAbility.php:42](../../vendor/flarum/tags/src/Access/ScopeDiscussionVisibilityForAbility.php#L42)

### C. Schema field visibility

- **`->visible(fn ... => $context->getActor()->isAdmin())`** — hide admin-only flags from non-admins.
  [vendor/flarum/tags/src/Api/Resource/TagResource.php:114](../../vendor/flarum/tags/src/Api/Resource/TagResource.php#L114)

- **Per-resource ability re-evaluated inside `->writable()`** — prevents mass-PATCH bypass.
  [vendor/flarum/likes/src/Api/PostResourceFields.php:29](../../vendor/flarum/likes/src/Api/PostResourceFields.php#L29)

- **One closure reused for both `visible()` and `writable()`** — gates stay consistent.
  [vendor/flarum/suspend/src/Api/UserResourceFields.php:28](../../vendor/flarum/suspend/src/Api/UserResourceFields.php#L28)

### D. Custom endpoints

- **`Endpoint::make()->route()->authenticated()->can()->action()->response(EmptyResponse(204))`** — the recommended pipeline.
  [vendor/flarum/gdpr/src/Api/Resource/ErasureRequestResource.php:100](../../vendor/flarum/gdpr/src/Api/Resource/ErasureRequestResource.php#L100)

- **Re-confirm password before irreversible action** via an `Endpoint->before()` hook.
  [vendor/flarum/gdpr/src/Api/Resource/ErasureRequestResource.php:89](../../vendor/flarum/gdpr/src/Api/Resource/ErasureRequestResource.php#L89)

- **Classic admin-only controller** — `RequestUtil::getActor($request)->assertAdmin()` as the first line.
  [vendor/flarum/tags/src/Api/Controller/OrderTagsController.php:24](../../vendor/flarum/tags/src/Api/Controller/OrderTagsController.php#L24)

### E. Notifications

- **`Blueprint::getData()` returns null or primitive scalars only** — never raw content.
  [vendor/flarum/likes/src/Notification/PostLikedBlueprint.php:36](../../vendor/flarum/likes/src/Notification/PostLikedBlueprint.php#L36)

- **`Extend\Notification::beforeSending` filter** — strip recipients who can't see the underlying object (CRITICAL when blueprint subject is broader than the leaking object).
  [vendor/flarum/subscriptions/src/Notification/FilterVisiblePostsBeforeSending.php:24](../../vendor/flarum/subscriptions/src/Notification/FilterVisiblePostsBeforeSending.php#L24)

### F. Validators (v2 style)

- **Schema-level chained validators** with translator-keyed messages — v2 replaces `AbstractValidator` for most field-level validation.
  [vendor/flarum/nicknames/src/Api/UserResourceFields.php:36](../../vendor/flarum/nicknames/src/Api/UserResourceFields.php#L36)

- **`not_regex` to reject email-rendering attack chars** (`[]()<>` would render as auto-linked markdown in some clients).
  [vendor/flarum/nicknames/src/Api/UserResourceFields.php:44](../../vendor/flarum/nicknames/src/Api/UserResourceFields.php#L44)

- **Uniqueness across TWO columns** (nickname AND username) — blocks impersonation.
  [vendor/flarum/nicknames/src/Api/UserResourceFields.php:48](../../vendor/flarum/nicknames/src/Api/UserResourceFields.php#L48)

### G. Settings

- **`serializeToForum` with a sanitizer cast** (e.g. `'boolVal'`) — strings get cast to typed JS values.
  [vendor/flarum/gdpr/extend.php:60](../../vendor/flarum/gdpr/extend.php#L60)

- **No official extension serializes secrets via `serializeToForum`.** Secrets stay server-side; admin-controlled raw HTML doesn't exist in first-party extensions. Mirror this discipline.

### H. Filters / Search

- **Slug-to-ID resolution with `whereVisibleTo($actor)`** — slugs the actor can't see degrade to "no match" instead of leaking existence.
  [vendor/flarum/tags/src/Search/Filter/TagFilter.php:58](../../vendor/flarum/tags/src/Search/Filter/TagFilter.php#L58)

- **Regex allowlist on filter input** — user value goes through `preg_match('/^(follow|ignor)(?:ing|ed)$/i', ...)` before reaching SQL.
  [vendor/flarum/subscriptions/src/Filter/SubscriptionFilter.php:35](../../vendor/flarum/subscriptions/src/Filter/SubscriptionFilter.php#L35)

### I. Migrations

- **Composite primary key + cascade-on-delete on a pivot table** — prevents orphan rows re-exposing deleted content.
  [vendor/flarum/tags/migrations/2023_03_01_000000_create_post_mentions_tag_table.php:36](../../vendor/flarum/tags/migrations/2023_03_01_000000_create_post_mentions_tag_table.php#L36)

- **Pre-FK orphan cleanup** — delete dangling rows before adding the FK, so the migration doesn't crash on dirty installs.
  [vendor/flarum/flags/migrations/2018_06_27_101600_change_flags_add_foreign_keys.php:17](../../vendor/flarum/flags/migrations/2018_06_27_101600_change_flags_add_foreign_keys.php#L17)

- **Enum column as DB-level input allowlist** — `['follow','ignore']` enforced at storage layer.
  [vendor/flarum/subscriptions/migrations/2015_05_11_000000_add_subscription_to_users_discussions_table.php:12](../../vendor/flarum/subscriptions/migrations/2015_05_11_000000_add_subscription_to_users_discussions_table.php#L12)

### J. Frontend

- **`extend(DiscussionControls, 'moderationControls', …)` gated on a backend-computed `can*` boolean** — frontend never re-implements the policy.
  [vendor/flarum/tags/js/src/forum/addTagControl.js:7](../../vendor/flarum/tags/js/src/forum/addTagControl.js#L7)

- **No `m.trust(...)` in any surveyed first-party extension.** Output goes through s9e/TextFormatter XSL templates or backend-computed schema attributes.

### K. Middleware / runtime hooks

- **`Extend\User->permissionGroups()` runtime demotion** — instead of writing custom middleware to block suspended users, `flarum/suspend` demotes them to `GUEST_ID` at permission resolution time. Cleaner than middleware ordering.
  [vendor/flarum/suspend/src/RevokeAccessFromSuspendedUsers.php:18](../../vendor/flarum/suspend/src/RevokeAccessFromSuspendedUsers.php#L18) wired at [vendor/flarum/suspend/extend.php:64](../../vendor/flarum/suspend/extend.php#L64)

### L. Tag access cascades (CRITICAL when discussions are involved)

- **Permission slug `tag{id}.discussion.{ability}`** — discussion abilities gated through tag restrictions.
  [vendor/flarum/tags/src/Access/DiscussionPolicy.php:30](../../vendor/flarum/tags/src/Access/DiscussionPolicy.php#L30)

- **`whereHasPermission($actor, $permission)`** on the Tag relation — query-level enforcement.
  [vendor/flarum/flags/src/Access/ScopeFlagVisibility.php:33](../../vendor/flarum/flags/src/Access/ScopeFlagVisibility.php#L33)

- **THREE layers of defense** for restricted tags: `ScopeTagVisibility` (hides tag rows) + `ScopeDiscussionVisibilityForAbility` (hides discussion rows) + `DiscussionPolicy::can()` (denies actions if a discussion is loaded anyway). Any extension loading discussions via raw IDs needs all three checks.

### M. Mentions (input sanitization at parser level)

- **Type coercion via `#uint` filterChain** + runtime permission check that invalidates the tag.
  [vendor/flarum/mentions/src/ConfigureMentions.php:59](../../vendor/flarum/mentions/src/ConfigureMentions.php#L59) and [vendor/flarum/mentions/src/ConfigureMentions.php:242](../../vendor/flarum/mentions/src/ConfigureMentions.php#L242)

- **Regex-constrained username charset at parse time** — `USER_MENTION_WITH_USERNAME_REGEX = '/\B@(?<username>[a-z0-9_-]+)(?!#)/i'`. Defeats Unicode lookalike attacks.

### N. Subscriptions (per-user scoped state)

- **Per-user state pivoted through `discussion_user`** with `->where('user_id', $actor->id)` on every read path. There is **no public listing endpoint** — user A cannot enumerate B's subscriptions.
  [vendor/flarum/subscriptions/src/Filter/SubscriptionFilter.php:43](../../vendor/flarum/subscriptions/src/Filter/SubscriptionFilter.php#L43)

### O. GDPR (data lifecycle)

- **Fixed-order data type registration** — `Data\User::class` MUST run last because anonymization renames the user; reordering re-leaks the old username.
  [vendor/flarum/gdpr/src/DataProcessor.php:26](../../vendor/flarum/gdpr/src/DataProcessor.php#L26)

- **Inverse-default authorization for anonymized users** — `reservedAbilities` container binding denies EVERY ability by default, with an opt-in allowlist.
  [vendor/flarum/gdpr/src/Providers/GdprProvider.php:30](../../vendor/flarum/gdpr/src/Providers/GdprProvider.php#L30) + [vendor/flarum/gdpr/src/Access/UserPolicy.php:27](../../vendor/flarum/gdpr/src/Access/UserPolicy.php#L27)

- **Capability URL caveat** — `ExportController` has no actor check; relies on the random filename being unguessable. If you copy this pattern, accept the threat model OR mirror `ConfirmErasureController` which DOES verify actor identity.
  [vendor/flarum/gdpr/src/Http/Controller/ExportController.php:29](../../vendor/flarum/gdpr/src/Http/Controller/ExportController.php#L29) vs [vendor/flarum/gdpr/src/Http/Controller/ConfirmErasureController.php:44](../../vendor/flarum/gdpr/src/Http/Controller/ConfirmErasureController.php#L44)

### P. Surprising-but-good patterns worth imitating

- **`WeakMap` permission cache per-User instance**, with explicit `flush()` for queue workers — naive `static` caching would leak between users.
  [vendor/flarum/tags/src/Tag.php:236](../../vendor/flarum/tags/src/Tag.php#L236)

- **Clear stale display text on state change** — when `suspended_until` is cleared, `suspend_reason` and `suspend_message` are nulled in the same save to prevent stale moderator notes leaking.
  [vendor/flarum/suspend/src/Listener/SavingUser.php:30](../../vendor/flarum/suspend/src/Listener/SavingUser.php#L30)

### Q. Anti-patterns observed even in first-party code

- **`flarum/likes` has no rate limiting on toggle.** Spam is only prevented by idempotent attach/detach + notification row deletion. If you build a toggle-style feature with side effects (notifications, emails), add explicit throttling — the official extension doesn't, and that's a known gap.
- **`flarum/mentions` has no notification dedupe.** Mention five times in one post → five notification rows. Watch for this in your own extensions.

---

## Where to start when writing a NEW extension

1. **Read this CLAUDE.md end-to-end once.**
2. **Pick the closest first-party extension to your use case** and read its full source. Suggested mapping:
   - Building per-user state with subscriptions? → `flarum/subscriptions`
   - Building per-user-data lifecycle (delete/export)? → `flarum/gdpr`
   - Building admin moderation tools? → `flarum/suspend` + `flarum/flags`
   - Building a tag-like restricted-content system? → `flarum/tags`
   - Building user input that mentions/links other users? → `flarum/mentions` + `flarum/nicknames`
   - Building an upvote/reaction system? → `flarum/likes`
3. **Mirror its `extend.php` shape, its Resource shape, its Policy shape.** Don't invent.
4. **Run the §32 checklist before every commit.**

---

## §35. CI/CD & GitHub Actions workflows

This section documents the reference CI/CD setup used by this repository (the same
extension that ships this `CLAUDE.md`). The workflow templates live in
`.github/workflows/` and the associated config files in `.github/`. When working on any
Flarum v2 extension that lacks these files, **Claude should offer to scaffold them**
(see the prompt at the end of this section).

The goal is to provide every Flarum v2 extension with:

- **Lint + build verification** on every push and PR (so broken PHP or webpack builds never reach `main`).
- **Automatic release publication** when the `composer.json` version bumps.
- **Forum announcement** posting the release notes to a configured Flarum discussion.
- **Old release cleanup** keeping the GitHub releases page tidy.
- **Branch hygiene** auto-labeling PRs and keeping feature branches in sync with `main`.

### 35.1 The seven-file workflow set

| File | Trigger | Purpose |
|---|---|---|
| `.github/workflows/ci.yml` | `push` to `main`, `pull_request`, manual | PHP lint matrix (8.2/8.3/8.4) + composer validate + JS prettier check + webpack production build |
| `.github/workflows/release-management.yml` | `push` to `main` | Detects `composer.json` version change → drafts and publishes a GitHub release → posts to Flarum forum |
| `.github/workflows/publish-to-flarum.yml` | `release` event, manual dispatch | Standalone Flarum-forum-post job (used when a release is published outside the auto pipeline) |
| `.github/workflows/cleanup-releases.yml` | Manual dispatch | Keeps only the last 5 releases; deletes older releases + tags |
| `.github/workflows/pr-labeler.yml` | `pull_request` opened/reopened/sync | Auto-applies a label to the PR based on the source branch prefix |
| `.github/workflows/sync-branches.yml` | `push` to `main`, manual | Merges `main` into every other branch (skips `copilot/*`); skips on conflict |
| `.github/pr-labeler.yml` (config) | — | Mapping `branch-prefix/*` → `label-name` |
| `.github/release-drafter.yml` (config) | — | Category-based changelog template + version-resolver rules |

### 35.2 CI workflow (`ci.yml`) — gate every change

The CI workflow runs on every push to `main` and every PR. **A PR that fails CI must
not be merged.** It has two parallel jobs:

**Job 1 — PHP matrix** (one runner per PHP version):
```yaml
name: CI
on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:
concurrency:                                       # cancel stacked runs on same ref
  group: ci-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
permissions:
  contents: read
jobs:
  php:
    name: PHP ${{ matrix.php }}
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        php: ['8.2', '8.3', '8.4']
    steps:
      - uses: actions/checkout@v4
      - uses: shivammathur/setup-php@accd6127cb78bee3e8082180cb391013d204ef9f  # v2 pinned
        with:
          php-version: ${{ matrix.php }}
          coverage: none
          tools: composer:v2
      - name: Validate composer.json
        run: composer validate --strict --no-check-publish --no-check-version
      - name: Lint PHP (php -l)
        run: |
          set -euo pipefail
          mapfile -d '' files < <(find src migrations extend.php -name '*.php' -print0 2>/dev/null)
          [ "${#files[@]}" -gt 0 ] || { echo "No PHP files found"; exit 1; }
          printf '%s\0' "${files[@]}" | xargs -0 -n1 -P4 php -l
```

**Job 2 — JS build** (single runner):
```yaml
  js:
    name: JS (format, build)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: 'npm'
          cache-dependency-path: js/package-lock.json
      - working-directory: js
        run: npm ci
      - working-directory: js
        run: npm run format-check                  # Prettier
      - working-directory: js
        run: npm run build                         # webpack production
```

**Design notes**:
- `--no-check-version` silences "version field is present" — the version field is **kept on purpose** so `EndBug/version-check` in the release workflow can detect bumps. All other composer warnings remain fatal.
- The PHP matrix covers the three current LTS-ish PHP versions Flarum v2 supports.
- The action SHA pinning on `shivammathur/setup-php` is intentional security hardening (don't trust mutable tags).
- `concurrency` cancels stacked runs on the same PR so you don't waste minutes when force-pushing.

### 35.3 Release management (`release-management.yml`) — auto-release on version bump

The release workflow watches `main` for `composer.json` version bumps. When one is
detected, it:

1. Runs the JS build (so `js/dist/*` artifacts are fresh).
2. Calls `release-drafter/release-drafter` to assemble the changelog from merged PRs (grouped by label per `.github/release-drafter.yml`).
3. Publishes the GitHub release with tag `v<version>`.
4. Posts release notes to the configured Flarum forum discussion (if `vars.FLARUM_DISCUSSION_ID` is set).

Skeleton (full file at `.github/workflows/release-management.yml`):

```yaml
name: Release Workflow
on:
  push:
    branches: [main]
jobs:
  build_and_release:
    runs-on: ubuntu-latest
    permissions:
      contents: write          # required to create releases
      pull-requests: read      # required by release-drafter to read merged PRs
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }                   # full history for changelog generation

      - uses: actions/setup-node@v4
        with: { node-version: 20, cache: 'npm', cache-dependency-path: js/package-lock.json }

      - run: cd js && npm ci && npm run build

      - id: check_version
        uses: EndBug/version-check@d17247dd94ca7b39d0b0691399be8d7c510622c9   # v2 pinned
        with:
          file-name: composer.json
          diff-search: true

      - id: create_release
        if: steps.check_version.outputs.changed == 'true'
        uses: release-drafter/release-drafter@6a93d829887aa2e0748befe2e808c66c0ec6e4c7  # v6 pinned
        with:
          publish: true
          tag: v${{ steps.check_version.outputs.version }}
          name: v${{ steps.check_version.outputs.version }}
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Post release to Flarum forum
        if: |
          steps.check_version.outputs.changed == 'true'
          && steps.create_release.outcome == 'success'
          && steps.create_release.outputs.html_url
          && vars.FLARUM_DISCUSSION_ID != ''
        env:
          FLARUM_API_KEY: ${{ secrets.FLARUM_API_KEY }}
          FLARUM_DISCUSSION_ID: ${{ vars.FLARUM_DISCUSSION_ID }}
          RELEASE_TAG:  ${{ steps.create_release.outputs.tag_name }}
          RELEASE_BODY: ${{ steps.create_release.outputs.body }}
          RELEASE_URL:  ${{ steps.create_release.outputs.html_url }}
        run: |
          VERSION="${RELEASE_TAG#v}"
          PAYLOAD=$(jq -n \
            --arg tag "$RELEASE_TAG" --arg body "$RELEASE_BODY" \
            --arg url "$RELEASE_URL" --arg version "$VERSION" \
            --arg did "$FLARUM_DISCUSSION_ID" \
            '{ data: { type:"posts",
                attributes: { content: ("## "+$tag+"\n\n"+$body+"\n\n**Install:**\n```\ncomposer require vendor/ext:"+$version+"\n```\n\n[See release on GitHub]("+$url+")") },
                relationships: { discussion: { data: { type:"discussions", id:$did } } } } }')
          HTTP=$(curl -s -o /tmp/r.json -w "%{http_code}" \
            -X POST "https://YOUR-FORUM.example/api/posts" \
            -H "Authorization: Token ${FLARUM_API_KEY}" \
            -H "Content-Type: application/json" \
            -d "$PAYLOAD")
          [ "$HTTP" -ge 200 ] && [ "$HTTP" -lt 300 ] || { jq . /tmp/r.json; exit 1; }
```

**Critical security notes**:
- The Flarum API call uses `Authorization: Token <FLARUM_API_KEY>` — per §17, this is a session token bound to an admin user. **Never use an unbound `ApiKey` here** — that would be a master key.
- `jq -n --arg` is used to build JSON, not string interpolation, because the release body contains arbitrary user content (PR titles, markdown). Building JSON by `echo "{\"content\":\"$body\"}"` is a JSON-injection vector.
- The forum hostname (`https://YOUR-FORUM.example`) must be hardcoded in the workflow YAML — never sourced from a variable that an admin can change without code review.

### 35.4 Standalone forum publisher (`publish-to-flarum.yml`)

Same JSON payload as §35.3, but triggered by `on: release: types: [published]` or
`workflow_dispatch`. Useful when:

- A release is created manually (not via the auto pipeline).
- A previous Flarum post failed and needs retry via manual dispatch.
- A different repo wants to post to the forum without owning the full release pipeline.

Inputs for manual dispatch:
- `release_tag` (required) — e.g. `v2.0.6`
- `release_body` (optional)
- `release_url` (optional)

### 35.5 Cleanup old releases (`cleanup-releases.yml`)

Manual-dispatch-only workflow that keeps the **last 5 releases** and deletes older ones
+ their tags. Prevents the releases page from accumulating hundreds of patch versions.

```yaml
name: Cleanup Old Releases
on:
  workflow_dispatch:
jobs:
  cleanup:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/github-script@v7
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          script: |
            const KEEP = 5;
            const releases = await github.paginate(
              github.rest.repos.listReleases,
              { owner: context.repo.owner, repo: context.repo.repo, per_page: 100 }
            );
            releases.sort((a, b) => new Date(b.published_at) - new Date(a.published_at));
            const toDelete = releases.slice(KEEP);
            for (const r of toDelete) {
              await github.rest.repos.deleteRelease({
                owner: context.repo.owner, repo: context.repo.repo, release_id: r.id });
              try {
                await github.rest.git.deleteRef({
                  owner: context.repo.owner, repo: context.repo.repo,
                  ref: `tags/${r.tag_name}` });
              } catch (e) { /* tag already gone */ }
            }
```

Only run on demand — destructive operation.

### 35.6 PR Labeler (`pr-labeler.yml` + `.github/pr-labeler.yml`)

Automatically applies a label to every PR based on the source branch prefix.
Drives the changelog grouping in §35.3.

Workflow:
```yaml
name: PR Labeler
on:
  pull_request:
    types: [opened, reopened, synchronize]
jobs:
  label_pr:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: TimonVS/pr-labeler-action@f9c084306ce8b3f488a8f3ee1ccedc6da131d1af  # v5.0.0 pinned
        with:
          configuration-path: .github/pr-labeler.yml
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

Config (`.github/pr-labeler.yml`) — branch prefix → label mapping (the reference
extension uses Portuguese labels; adapt to your team's vocabulary):
```yaml
BC: bc/*
melhoria: melhoria/*                     # improvement / minor
correcao: ['correcao/*', 'conserto/*', 'ajuste/*']  # bug fix / patch
dependencias: dependencias/*             # dependency bumps
documentacao: ['docs/*', 'documentacao/*']
manutencao: manutencao/*                 # chore / maintenance
performance: performance/*
traducao: traducao/*                     # i18n
refatoracao: refatoracao/*               # refactor (no behavior change)
'pular changelog': release/*             # release/* branches are excluded from changelog
```

English-equivalent labels you may prefer:
```yaml
breaking: bc/*
feat: feat/*
fix: ['fix/*', 'bug/*']
deps: deps/*
docs: docs/*
chore: chore/*
perf: perf/*
i18n: i18n/*
refactor: refactor/*
'skip-changelog': release/*
```

If you change the label names, update `.github/release-drafter.yml` to match.

### 35.7 Branch sync (`sync-branches.yml`)

When `main` advances, merge it into every other branch (skipping `copilot/*` for AI
PRs and skipping branches with conflicts). Keeps long-running feature branches from
diverging.

```yaml
name: Sync Branches with Main
on:
  push:
    branches: [main]
  workflow_dispatch:
concurrency:
  group: sync-branches                              # one at a time
  cancel-in-progress: false
jobs:
  sync:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          token: ${{ secrets.GITHUB_TOKEN }}
      - run: |
          git config user.name  "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git fetch --all
          BRANCHES=$(git branch -r \
            | grep -v 'HEAD' \
            | grep -v 'origin/main' \
            | grep -v 'origin/copilot/' \
            | sed 's|origin/||' | tr -d ' ')
          for branch in $BRANCHES; do
            git checkout -B "$branch" "origin/$branch"
            if git merge origin/main --no-edit -m "chore: sync with main"; then
              git push origin "$branch"
            else
              git merge --abort
            fi
          done
```

**Footguns**:
- On conflict, the script aborts the merge for that branch and continues — it does NOT force-push or rewrite history. Manual resolution is required.
- `copilot/*` branches are excluded so AI-generated PRs aren't churned with merge commits.
- Never use `git push --force` here — that would clobber commits other contributors made on their branches.

### 35.8 Release Drafter config (`.github/release-drafter.yml`)

Drives the changelog body and version-bump-from-labels logic. Reference shape:

```yaml
name-template: 'v$RESOLVED_VERSION'
tag-template: 'v$RESOLVED_VERSION'
exclude-labels:
  - 'skip-changelog'
categories:
  - title: 'Breaking Changes'
    labels: ['breaking']
  - title: 'Features'
    labels: ['feat']
  - title: 'Bug Fixes'
    labels: ['fix']
  - title: 'Performance'
    labels: ['perf']
  - title: 'Documentation'
    labels: ['docs']
  - title: 'Refactor'
    labels: ['refactor']
  - title: 'Dependencies'
    labels: ['deps']
  - title: 'i18n'
    labels: ['i18n']
  - title: 'Chore'
    labels: ['chore']
version-resolver:
  major:
    labels: ['breaking']
  minor:
    labels: ['feat']
  patch:
    labels: ['fix']
  default: patch
change-template: '- $TITLE (PR #$NUMBER) by @$AUTHOR'
template: |
  ## What changed
  $CHANGES

  ## How to update

  ```bash
  composer require vendor/ext:$RESOLVED_VERSION
  php flarum cache:clear
  php flarum assets:publish
  ```
```

### 35.9 Required secrets and variables

For the workflows above to function, the repository must have these configured under
**Settings → Secrets and variables → Actions**:

| Name | Type | Used by | Notes |
|---|---|---|---|
| `GITHUB_TOKEN` | (auto) | all | Provided automatically by Actions; no setup. |
| `FLARUM_API_KEY` | Secret | release-management, publish-to-flarum | **Session token bound to an admin user**, NOT an unbound `ApiKey` (see §17). Rotate periodically. |
| `FLARUM_DISCUSSION_ID` | Variable | release-management, publish-to-flarum | Numeric ID of the forum discussion where release notes are posted. Empty → forum-post step is skipped. |

If `FLARUM_DISCUSSION_ID` is unset, the workflows skip the forum-post step gracefully —
the GitHub release is still created.

### 35.10 Security hardening of the workflows themselves (baseline level)

**This subsection covers the baseline hardening already present. §35.13 documents
additional hardening that should be applied before 2026 production deployment.**

- **Third-party actions are SHA-pinned**, not tag-pinned (`shivammathur/setup-php@accd6127...` not `@v2`). This protects against the malicious-tag-move attack class (CVE-2025-30066, see §35.13/C3). **GitHub-owned actions (`actions/checkout`, `actions/setup-node`, `actions/github-script`) are still tag-pinned in this baseline — see §35.13/C2 to tighten.**
- **`permissions:` is set explicitly per job** — least-privilege. CI is `contents: read`; release is `contents: write` + `pull-requests: read`; cleanup is `contents: write` only.
- **Top-level `permissions: {}` (default-deny)** is set only on `publish-to-flarum.yml`. The other six workflows should add it as defense-in-depth — see §35.13/C1.
- **`concurrency:` prevents stacked runs** on the same ref (CI cancels in-progress; sync-branches queues). Note: `release-management.yml` and `cleanup-releases.yml` lack `concurrency:` — see §35.13/I4.
- **No untrusted action input flows into a `run:` block via interpolation.** All user-controlled values (release bodies, PR titles) reach `run:` as environment variables and are passed to `jq --arg` for JSON construction — never `echo`-concatenated.
- **`publish-to-flarum.yml` uses `permissions: {}`** (empty) because it only calls an external API; it doesn't need GitHub write access.
- **Secrets are not logged.** The workflows print `HTTP Status: $HTTP` and the response body, but the request body (which contains the secret only in the Authorization header) is not echoed.

### 35.11 What's NOT in this workflow set (intentional gaps)

- **No deploy step.** Flarum extensions are installed via `composer require` on the host forum; there's no "deploy" target. The release IS the deploy.
- **No Packagist auto-submit.** If the extension is hosted on Packagist with the GitHub webhook configured, Packagist updates automatically on tag push — no workflow needed. Otherwise, add a manual `packagist.org` push step (out of scope for this template).
- **No phpunit/integration tests.** Flarum extensions rarely ship test suites; if yours does, add a third matrix job to `ci.yml`.
- **No type-checking step for TypeScript projects.** If your extension uses TypeScript (the reference repo here uses plain JS), add `npm run check-typings` (`tsc --noEmit`) before the build step.
- **No SAST/dependency scanning.** Consider GitHub's built-in Dependabot + CodeQL; configure separately under repo Settings.

### 35.12 Branch naming convention (must match the labeler config)

The labeler maps **branch prefix → label**, so your branch names must follow the prefix
contract. Reference contract:

```
breaking/<short-name>      → 'breaking' label  → major version bump
feat/<short-name>          → 'feat'     label  → minor version bump
fix/<short-name>           → 'fix'      label  → patch version bump
docs/<short-name>          → 'docs'     label
deps/<short-name>          → 'deps'     label
perf/<short-name>          → 'perf'     label
i18n/<short-name>          → 'i18n'     label
refactor/<short-name>      → 'refactor' label
chore/<short-name>         → 'chore'    label
release/<short-name>       → 'skip-changelog' label  → excluded from changelog
```

PRs without a recognized prefix get NO label — they appear at the bottom of the
changelog ungrouped. Don't ignore unlabeled PRs at release time.

### 35.13 Hardening roadmap — gaps beyond the baseline (severity-tiered)

The seven workflows in §35.1–35.12 are the **baseline**. They cover lint, build, release,
and forum announcement. The list below documents **upgrades** that any extension
targeting production deployment in 2026+ should consider. Severity tiers follow §33 —
🔴 critical, 🟠 important, 🟡 recommended, ⚪ optional.

When scaffolding workflows (§35.17), Claude should mention this roadmap to the user and
offer to apply the 🔴 critical items by default unless the user opts out.

#### 🔴 Critical — apply before production

**C1. Missing `permissions:` at workflow level — over-privileged `GITHUB_TOKEN`.**
The GitHub Actions default grants `GITHUB_TOKEN` a broad scope (in non-public repos,
`contents: write` by default), opening a path for a malicious PR to modify releases,
push tags, or alter workflow files. Canonical mitigation: top-level `permissions: {}`
+ explicit per-job grant.

```yaml
# At the very top of every workflow file
permissions: {}        # default-deny

jobs:
  build:
    permissions:
      contents: read   # only what this job needs
    # ...
```

Source: [docs.github.com — Assigning permissions to jobs](https://docs.github.com/actions/security-guides/automatic-token-authentication).
The seven baseline workflows in this repo already do this per-job, but **`permissions: {}`
should also be set at the file top** as a defense-in-depth default-deny — currently only
`publish-to-flarum.yml` has it.

**C2. SHA pinning even for GitHub-owned actions.**
The Flarum-recommended pattern at [docs.flarum.org/extend/github-actions](https://docs.flarum.org/extend/github-actions/)
uses `uses: flarum/framework/.github/workflows/REUSABLE_backend.yml@main` — a reference
to a **mobile branch**. The OpenSSF Scorecard `Pinned-Dependencies` check is rated
Medium severity (weight 5/10), with internal scoring where third-party actions weigh 8
and GitHub-owned actions weigh 2. Mid-tier weight, but real impact is high when combined
with C3.

The baseline workflows in this repo pin **third-party actions by SHA**
(`shivammathur/setup-php@accd6127...`, `EndBug/version-check@d17247dd...`,
`release-drafter/release-drafter@6a93d829...`, `TimonVS/pr-labeler-action@f9c08430...`)
but leave **GitHub-owned actions tag-pinned** (`actions/checkout@v4`, `actions/setup-node@v4`,
`actions/github-script@v7`). Tighten to SHA on the GitHub-owned ones too:

```yaml
# Before
- uses: actions/checkout@v4
- uses: actions/setup-node@v4
- uses: actions/github-script@v7

# After — SHA pinned (look up current SHA at the action's repo tag page)
- uses: actions/checkout@<full-40-char-sha>            # v4.x
- uses: actions/setup-node@<full-40-char-sha>          # v4.x
- uses: actions/github-script@<full-40-char-sha>       # v7.x
```

Maintain a `# vN.x.y` comment next to each SHA so Dependabot (R1 below) can keep them
fresh while preserving the pin.

**C3. Tag pinning is no longer sufficient — the 2025 incident chain.**
On **14–15 March 2025**, `tj-actions/changed-files` was compromised
([GHSA-mrrh-fwg8-r2c3](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3) /
CVE-2025-30066), affecting **over 23,000 repositories**
(source: [The Hacker News, 2025-03-15 — "GitHub Action Compromise Puts CI/CD Secrets at
Risk in Over 23,000 Repositories"](https://thehackernews.com/2025/03/github-action-compromise-puts-cicd.html)).
Multiple tags were **re-pointed to a malicious commit** that exfiltrated runner secrets
via `echo` to the workflow log. Repositories that pinned by SHA were **immune**.

Wiz Research determined the upstream causal vector was `reviewdog/action-setup`
([GHSA-qmg3-hpqr-gqvc](https://github.com/advisories/GHSA-qmg3-hpqr-gqvc) /
CVE-2025-30154), where only the `v1` tag was re-pointed during a **108-minute window
(18:42–20:31 UTC on 11 March 2025)**. That compromise stole a PAT which was then used
to compromise `tj-actions`.

**Operational rule for 2026**: **SHA-pin every `uses:` directive in every workflow.**
Tag pinning — including from GitHub-owned actions — is insufficient. The seven
baseline workflows partially comply; full compliance is the C2 fix.

**C4. The Flarum-recommended reusable workflow points at `@main`.**
If you adopt `flarum/framework/.github/workflows/REUSABLE_backend.yml@main` as the
official Flarum docs suggest, you are taking a mobile branch reference. **Pin to a
specific SHA** of the reusable workflow's commit — accept the maintenance cost. If the
Flarum maintainers update the reusable workflow with breaking changes, Dependabot will
PR the SHA bump for review.

#### 🟠 Important — apply before next release

**I1. `actions/dependency-review-action` on every PR.**
Blocks PRs that introduce dependencies with known CVEs (`composer.lock` / `package-lock.json`)
before merge. Free for public repos.

```yaml
# .github/workflows/ci.yml — add as a third job
  dependency-review:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@<sha>
      - uses: actions/dependency-review-action@<sha>
        with:
          fail-on-severity: high
          comment-summary-in-pr: on-failure
```

**I2. CodeQL with `security-extended` queries for JS/TS.**
Detects whole classes of bugs (XSS, prototype pollution, path traversal, command
injection). Free for public repos.

**Important caveat — CodeQL does NOT support PHP** and never has. The supported
languages list at [docs.github.com/code-security/code-scanning](https://docs.github.com/code-security/code-scanning)
does not include PHP. What was retired on **10 January 2025** was the **CodeQL Action
v2** (deprecation due to Node.js runtime constraints — source:
[GitHub Changelog 2025-01-10 — "CodeQL Action v2 is now retired"](https://github.blog/changelog/2025-01-10-codeql-action-v2-is-now-retired/)) —
not PHP support, which has never existed.

For **JS/TS** (frontend `js/` directory) add CodeQL:
```yaml
# .github/workflows/codeql.yml
name: CodeQL
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 6 * * 1'                        # weekly
permissions: {}
jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    strategy:
      matrix:
        language: [javascript-typescript]
    steps:
      - uses: actions/checkout@<sha>
      - uses: github/codeql-action/init@<sha>
        with:
          languages: ${{ matrix.language }}
          queries: security-extended
      - uses: github/codeql-action/analyze@<sha>
```

For **PHP** (backend `src/` directory) use one of:
- **Semgrep** with `p/php` + `p/security-audit` rule sets (free for public repos via the Semgrep GitHub App).
- **PHPStan** with the `flarum/phpstan-stub` package (provides type information for Flarum 2.x core) + **Psalm taint analysis** for data-flow checks.

**I3. `step-security/harden-runner` — auditable egress.**
Records every network request made during a workflow run and can block egress to
endpoints outside an explicit allowlist. **Critical after the 2025 action compromises
(C3)** — if a transitively-pulled action exfiltrates secrets, harden-runner catches it.

```yaml
# Add as the FIRST step in every job that touches secrets
steps:
  - uses: step-security/harden-runner@<sha>
    with:
      egress-policy: audit                      # start in audit, then promote to 'block'
      allowed-endpoints: >
        api.github.com:443
        codeload.github.com:443
        github.com:443
        objects.githubusercontent.com:443
        packagist.org:443
        repo.packagist.org:443
        registry.npmjs.org:443
```

After two weeks of `audit` mode, review the logged endpoints and promote to
`egress-policy: block`.

**I4. `concurrency:` on every workflow.**
With frequent merges to `main` (e.g., 15 releases in `flarum/verified` in a short
window), two concurrent runs of `release-management.yml` can race for the same tag /
release. The baseline `ci.yml` and `sync-branches.yml` have `concurrency:` set;
`release-management.yml` and `cleanup-releases.yml` should also have it:

```yaml
# release-management.yml
concurrency:
  group: release-${{ github.ref }}
  cancel-in-progress: false                     # do NOT cancel; queue
```

`cancel-in-progress: false` because cancelling a release mid-flight could leave a
half-published tag.

**I5. PHP × Flarum matrix.**
Official extensions `flarum/tags`, `flarum/sticky`, `flarum/approval` run a matrix
against both `flarum/core: 2.x-dev` AND `flarum/core: ^2.0.0-rc.1` via the
`REUSABLE_backend.yml`. Without this, **core regressions are only detected when users
report breakage**.

```yaml
# ci.yml — augment the PHP job
strategy:
  fail-fast: false
  matrix:
    php: ['8.2', '8.3', '8.4']
    flarum-core:
      - '^2.0.0-rc.1'
      - '2.x-dev'
steps:
  # ... checkout + setup-php ...
  - run: composer require --no-update "flarum/core:${{ matrix.flarum-core }}"
  - run: composer update --prefer-stable --no-progress
  - run: composer validate --strict --no-check-publish --no-check-version
  # PHP lint as before
```

#### 🟡 Recommended — meaningful gains for low effort

**R1. Dependabot config (`.github/dependabot.yml`).**
Zero cost, low friction, high value. Auto-PRs for security and version bumps across
`composer`, `npm`, and `github-actions` ecosystems.

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: composer
    directory: /
    schedule: { interval: weekly, day: monday }
    open-pull-requests-limit: 5
    labels: [deps]
  - package-ecosystem: npm
    directory: /js
    schedule: { interval: weekly, day: monday }
    open-pull-requests-limit: 5
    labels: [deps]
  - package-ecosystem: github-actions
    directory: /
    schedule: { interval: weekly, day: monday }
    open-pull-requests-limit: 5
    labels: [deps]
```

Use the label name that matches `.github/pr-labeler.yml` (§35.6).

**R2. Automated `composer audit` / `npm audit` in PR.**
Belt-and-braces on top of I1. `composer audit` checks against the
[Packagist security advisories database](https://packagist.org/security-advisories);
`npm audit` checks the npm advisories database.

```yaml
# Append to ci.yml php job
- run: composer audit --no-dev --format=plain
# Append to ci.yml js job
- working-directory: js
  run: npm audit --audit-level=high
```

`--audit-level=high` because `low`/`moderate` produce too much noise (transitive dev
deps); promote to `moderate` later.

**R3. PHPStan with `flarum/phpstan-stub`.**
The stub package provides type information for Flarum 2.x core, which is what makes
PHPStan at level 8 viable on Flarum-extension code (otherwise core types are `mixed`
and most rules don't fire). Add as a `composer require --dev` and a CI step:

```yaml
- run: composer require --dev "phpstan/phpstan:^1" "flarum/phpstan-stub:*"
- run: vendor/bin/phpstan analyse --level=max src/ extend.php
```

**R4. SLSA provenance / build attestation.**
`actions/attest-build-provenance@v2` produces signed provenance for release artifacts.
Trivial to enable in 2026; improves trust score on the Packagist + Aikido package
health surface (Packagist exposes the Aikido health analysis by default — source:
[aikido.dev — "Aikido Package Health is a public service that assigns a clear Health
Score… composed of five weighted categories"](https://www.aikido.dev/blog/packagist-aikido-package-health)
covering stability, maintenance, maturity, install-time scripts, and **provenance**).

```yaml
# release-management.yml — after release-drafter publishes
- uses: actions/attest-build-provenance@<sha>
  with:
    subject-path: 'composer.json,js/dist/*.js'
```

Requires `permissions: { id-token: write, attestations: write }` on the job.

#### ⚪ Optional — situational

**O1. SBOM (CycloneDX or SPDX) attached to each release.**
[anchore/sbom-action](https://github.com/anchore/sbom-action) generates a software
bill of materials and uploads it as a release asset. Useful for downstream consumers
doing vulnerability triage.

```yaml
- uses: anchore/sbom-action@<sha>
  with:
    format: cyclonedx-json
    output-file: sbom.cdx.json
- uses: softprops/action-gh-release@<sha>
  with:
    files: sbom.cdx.json
```

**O2. YAML linting for `locale/*.yml`.**
i18n extensions silently break when YAML is invalid — Flarum's translator skips the
malformed file rather than failing the boot. Catch it at PR time:

```yaml
# ci.yml — add as a fast job
  locale:
    runs-on: ubuntu-latest
    permissions: { contents: read }
    steps:
      - uses: actions/checkout@<sha>
      - uses: karancode/yamllint-github-action@<sha>
        with:
          yamllint_file_or_dir: locale
          yamllint_strict: true
```

**O3. sigstore / cosign signature on release tarballs.**
Adds keyless cryptographic signatures verifiable via the public Sigstore transparency
log. Higher operational overhead than SLSA attestations (O3 alternative); typically
not needed unless your extension targets regulated environments.

**O4. Renovate as a more flexible alternative to Dependabot (R1).**
Same scope (composer + npm + github-actions) but offers per-ecosystem schedules,
groupings, auto-merge rules, and custom datasources. Higher initial config cost; pays
off on repos with 50+ deps. Choose Renovate OR Dependabot, not both — they create
duplicate PRs.

### 35.14 Compliance status of this repository's baseline

A self-audit checkbox for the baseline workflows shipped in this repo:

| Item | Status | Action |
|---|---|---|
| C1 — top-level `permissions: {}` | partial (only `publish-to-flarum.yml`) | Add `permissions: {}` at file top of all 6 other workflows |
| C2 — SHA-pin GitHub-owned actions | not compliant (`@v4`, `@v7`) | Replace tag pins with full-40-char SHAs |
| C3 — SHA-pin all third-party | **compliant** (`shivammathur`, `EndBug`, `release-drafter`, `TimonVS`) | maintain via Dependabot R1 |
| C4 — pin reusable workflows | N/A (not used) | If adopting `flarum/framework` reusable, pin to SHA not `@main` |
| I1 — dependency-review-action | not present | Add to `ci.yml` |
| I2 — CodeQL JS/TS | not present | Add `codeql.yml` |
| I3 — harden-runner | not present | Add as first step of jobs touching secrets |
| I4 — `concurrency:` on release workflows | partial (only `ci.yml`, `sync-branches.yml`) | Add to `release-management.yml`, `cleanup-releases.yml` |
| I5 — PHP × Flarum-core matrix | not present | Augment matrix in `ci.yml` |
| R1 — Dependabot | not present | Add `.github/dependabot.yml` |
| R2 — composer/npm audit | not present | Append to `ci.yml` jobs |
| R3 — PHPStan + `flarum/phpstan-stub` | not present | Add dev dep + CI step |
| R4 — SLSA attestation | not present | Add `attest-build-provenance` step |

When Claude scaffolds workflows (§35.17), it should apply 🔴 C1, C2, C4 by default and
**ask the user** before applying 🟠 and 🟡 items (each has a small but non-zero
operational cost: more PR noise, longer CI runtime, additional config files).

### 35.15 Threat model for this CI/CD surface

For each tier above, the threat being mitigated:

- **C1** — Malicious PR from an outside contributor uses overly-permissive default
  `GITHUB_TOKEN` to push commits or delete releases.
- **C2/C3/C4** — A third-party action publisher (or anyone who compromises their PAT)
  re-points a tag to a malicious commit; the malicious code runs with the secrets of
  every consuming workflow.
- **I1** — A PR introduces a dependency with a known CVE before merge; without this,
  the CVE only surfaces on the next Dependabot run (post-merge).
- **I2** — Frontend code introduces XSS, prototype pollution, or path traversal via a
  pattern CodeQL recognizes; without this, the bug lives until the next manual review.
- **I3** — Compromised action exfiltrates `FLARUM_API_KEY` (the Flarum admin session
  token, §17) or `GITHUB_TOKEN` via outbound HTTP; without harden-runner, the egress is
  invisible.
- **I4** — Two release-management runs race on the same tag; one publishes, the other
  fails with confusing error; the half-published state requires manual cleanup.
- **I5** — Flarum core 2.x ships a breaking change; your extension installs cleanly on
  RC but breaks on dev; users report broken installs.
- **R1** — Dependency bump with a CVE-fix sits unmerged for weeks because no one
  noticed; meanwhile attackers know which version is vulnerable.
- **R2** — Same as R1 but for production lockfiles (deps already in tree).
- **R3** — Type bugs (passing `null` where `User` is required) reach production
  because PHP only catches them at runtime.
- **R4** — Downstream consumer can't verify that the published artifact corresponds to
  the source commit — supply-chain provenance is unauditable.

### 35.16 Quick "harden this workflow" checklist

For any new or existing workflow file, run through:

- [ ] Top-level `permissions: {}` (default-deny).
- [ ] Per-job `permissions:` block granting only what that job needs.
- [ ] Every `uses:` directive pinned to a full 40-char SHA (not `@v4`, `@main`, `@latest`).
- [ ] `# vN.x.y` comment next to each SHA so Dependabot can refresh.
- [ ] `concurrency:` set if the workflow mutates shared state (tags, releases, branches).
- [ ] No `${{ github.event.* }}` interpolation directly into `run:` blocks (script injection vector — use `env:` indirection).
- [ ] No untrusted PR head code executed with secrets (`pull_request_target` is risky — prefer `pull_request` for PRs from forks, or gate with `if: github.event.pull_request.head.repo.full_name == github.repository`).
- [ ] `step-security/harden-runner` as the first step of any job with secrets.
- [ ] No `${{ secrets.* }}` echoed to logs (mask is best-effort; treat any log line containing a secret as leaked).

### 35.17 Claude scaffolding prompt — END OF SECTION

**If you are a Claude session reading this file in a Flarum v2 extension repository
AND the repository has no `.github/workflows/` directory (or is missing one or more of
the seven baseline files), you SHOULD proactively offer to scaffold the workflow set
PLUS the 🔴 critical hardening items from §35.13.**

Phrase the offer roughly like this:

> "I noticed this extension doesn't have CI/CD workflows configured (`.github/workflows/`
> is missing or incomplete). The CLAUDE.md §35 documents a baseline set + a hardening
> roadmap. Here's what I can scaffold:
>
> **Baseline (always applied)** — §35.1–35.12:
> - `ci.yml` — PHP 8.2/8.3/8.4 lint matrix + JS build on every PR
> - `release-management.yml` — auto-release when `composer.json` version bumps
> - `publish-to-flarum.yml` — forum announcement (optional, gated on `FLARUM_DISCUSSION_ID`)
> - `cleanup-releases.yml` — keep last 5 releases (manual dispatch)
> - `pr-labeler.yml` + `.github/pr-labeler.yml` — branch prefix → label
> - `sync-branches.yml` — auto-merge `main` into feature branches
> - `.github/release-drafter.yml` — category-based changelog
>
> **🔴 Critical hardening (also applied by default unless you say no)** — §35.13:
> - C1: top-level `permissions: {}` on every workflow (default-deny token scope)
> - C2: SHA-pin all GitHub-owned actions (not just third-party) — the 2025 `tj-actions/changed-files` compromise (CVE-2025-30066) affected 23,000+ repos that used tag pinning
> - C4: pin any reusable workflow you adopt to a SHA, not `@main`
>
> **🟠 Important upgrades (I'll ask before adding)** — §35.13:
> - I1: `actions/dependency-review-action` (block PRs with CVE deps)
> - I2: CodeQL `security-extended` for JS/TS (no PHP support; for PHP add Semgrep/PHPStan separately)
> - I3: `step-security/harden-runner` (auditable egress — critical after the 2025 chain attacks)
> - I4: `concurrency:` on release workflows
> - I5: PHP × Flarum-core matrix (test against `^2.0.0-rc.1` AND `2.x-dev`)
>
> **🟡 Recommended (I'll ask)** — §35.13:
> - R1: Dependabot for composer/npm/github-actions
> - R2: `composer audit` + `npm audit --audit-level=high` in CI
> - R3: PHPStan with `flarum/phpstan-stub` at max level
> - R4: SLSA build provenance attestation on release artifacts
>
> **⚪ Optional (mention only, won't apply unless asked)** — §35.13:
> - O1 SBOM (CycloneDX), O2 YAML lint for `locale/`, O3 sigstore signing, O4 Renovate
>
> You'll also need to configure two repo secrets after scaffolding:
> - `FLARUM_API_KEY` (admin session token — see §17 for why NOT an unbound ApiKey)
> - `FLARUM_DISCUSSION_ID` (variable, optional — numeric ID of the announcement thread)
>
> Reply 'yes' to apply baseline + 🔴 critical, 'full' to also add 🟠 and 🟡, or
> 'partial: ci,release,deps' for a custom subset."

**Implementation rules when scaffolding**:

1. **Copy the YAML files** from the workbench reference (the repo where this CLAUDE.md lives, at `.github/workflows/` and `.github/`).
2. **Replace hardcoded extension-specific tokens**: the forum URL (`https://YOUR-FORUM.example`), the `composer require vendor/ext:` line, the `release-drafter.yml` heading "## What changed".
3. **Apply 🔴 C1 by default** — add `permissions: {}` at the top of every workflow file you write, even if the per-job permissions are already explicit. Defense in depth.
4. **Apply 🔴 C2 by default** — when writing `uses:` directives, SHA-pin every action (look up the current SHA at the action's repo and add a `# vN.x.y` comment). This applies to BOTH third-party AND GitHub-owned actions in 2026+.
5. **Apply 🔴 C4 by default** — if the user opts into using a `flarum/framework` reusable workflow, pin it to a SHA, not `@main`.
6. **Never replace existing SHA pins with tag pins.** Going from `@accd6127cb78bee3e8082180cb391013d204ef9f` to `@v2` is a security regression.
7. **Do not commit `js/dist/*` regeneration** in the scaffolding commit; the release workflow rebuilds it.
8. **For 🟠 and 🟡 items**: ask the user explicitly before adding each. Each has a small but non-zero operational cost — extra CI minutes, PR noise from Dependabot, new tool installs.
9. **After scaffolding**, run `find .github -type f` (or `dir .github /s /b` on Windows) and report the file tree to the user.
10. **Tell the user which secrets they need to add** via the GitHub UI (`Settings → Secrets and variables → Actions`). Do NOT attempt to set them via API.
11. **Add a one-line entry to `README.md`** linking to the workflow set: `## CI/CD` → "See `.github/workflows/`. Configuration via repo Settings → Secrets and variables → Actions."
12. **For C2 SHA lookups**: if you can't fetch the current SHA online, comment the line with `# TODO: SHA-pin — run \`git ls-remote https://github.com/<owner>/<repo> v<X>.<Y>.<Z>\` and replace`, and tell the user to run it before merging.

**When NOT to offer**:
- The repository already has all seven workflow files AND meets the §35.14 compliance table (idempotency check).
- The user explicitly said "I don't want CI" in this session or a prior remembered preference.
- The repo is not a Flarum extension (no `extend.php` or `composer.json` lacks `"type": "flarum-extension"`).

**When PARTIAL workflows exist** (some baseline files present, some hardening missing):
- Don't re-create existing files.
- Run the §35.14 compliance audit against what's there.
- Offer to add ONLY the missing items, with a diff preview when possible (`git diff --no-index /dev/null .github/dependabot.yml`).
- Default to applying 🔴 critical fixes without asking; ask for 🟠 / 🟡 / ⚪.

---

## When in doubt

1. **Read the relevant section above end-to-end** before writing code. This file is the single source of truth.
2. If a pattern isn't covered, grep the reference extensions for the closest analogue.
3. If still uncertain, **ask the user**. A confirming question costs nothing; a shipped vulnerability costs everything.
4. **Never disable security primitives "temporarily"** — `bypassCsrfToken`, `forceAllow`, `$guarded = []`, raw `m.trust` of unsanitized input, `ApiKey` with `user_id = NULL`, returning `false` from a throttler "to exempt admins". Temporary becomes permanent.
5. After committing, run `php -l`, `npm run build`, and at minimum a manual smoke test of the affected screens.
