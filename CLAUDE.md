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
- §36 **Shell command execution & external binaries** — `exec`/`proc_open`, FFmpeg/ImageMagick, argument injection, untrusted-media attack surface
- §37 **Frontend `Content` injectors** (`Extend\Frontend->content()`) — SSR cost, raw-HTML `<head>` injection, `ApiResource` duplication
- §38 **Performance, memory, N+1** — Schema `->get()` callbacks, in-memory buffering of downloads/exports, missing compound indexes, large blobs in `serializeToForum`, filter-in-PHP traps
- §39 **Flarum version compatibility** — composer constraint vs API surface (v1.x/v2.x), MySQL-only SQL in migrations, Eloquent vs `ConnectionInterface`
- §40 **Frontend robustness, TS discipline, CSS targeting** — `JSON.parse` traps, user-visible error UI, DOM scoping, `as any`, `color-mix()`, hardcoded truncation, helper deduplication, unreachable CSS
- §41 **Logging discipline** — inject PSR-3 `LoggerInterface`; ban `Illuminate\Support\Facades\Log`
- §42 **Project hygiene & scaffolding completeness** — empty-skeleton smell, `console.log` in dist, stale `extra.*` metadata, missing referenced assets, PHPStan disabled in CI
- §43 **Composer constraints & dependency contracts** — `flarum/core` version range matches API surface, sister-extension pinning, `require` vs `suggest`, optional integration guards (`class_exists`, `extension_enabled`)
- §44 **Long-lived process state & PHP global handlers** — `set_error_handler` must chain, static Eloquent properties leak across requests in Octane/queue workers, `resolve()`/`app('foo')` without `bound()` check
- §45 **Migrations on core tables** — companion-table convention, online-DDL impact on `users`/`discussions`/`posts`/`discussion_user`, never add columns to core
- §46 **Event listener / blueprint subject-type contracts** — subject must match the type the consumer expects; polymorphic `subject_type`/`subject_id` integrity; recipient filters on `beforeSending`
- §47 **Admin-controlled execution surfaces** — `createContextualFragment`, settings-as-`<script>`, `style.innerHTML` interpolation, custom-JS/custom-CSS settings panels
- §48 **Review report output contract** — when finishing a `/review` or `/security-review`, ask before emitting; required fields (timestamp, quality score, vibe-coded score, executive summary, findings table); scoring rubric; verdict thresholds (≥80 approved, ≥75 with concerns, <75 not for production)
- §49 **Cryptographic key material persisted in the `settings` table** — never write a private key in plaintext base64; default to envelope-encryption with a per-install derived key; refuse to persist when the host lacks the required AEAD primitive
- §50 **Synchronous heavy work in request handlers** — file post-processing, multi-step Stripe sync, archive extraction must dispatch to the queue with a `processing_status` column; the controller returns immediately
- §51 **Estilo de comentário — Flarum core, em PT-BR** — só docblocks, em PT-BR, curtos, só onde o código não fala sozinho; NUNCA `//` inline (separadores, trailing, ou standalone)
- §52 **No env vars in extensions** — gate features off `config.php`'s `'debug' => true/false` via `Flarum\Foundation\Config`; never read `.env` or `getenv()` directly
- §53 **Handlers gordos** — `handle()` acima de ~100 linhas é refator obrigatório; extraia gates, validators, builders para `src/Service/<Domain>/`
- §54 **Laravel Filesystem vs I/O nativo** — sempre `Illuminate\Contracts\Filesystem\Factory`; exceções (ZipArchive, php_strip_whitespace) ficam isoladas e usam `Flarum\Foundation\Paths` no construtor, jamais `sys_get_temp_dir`
- §55 **Pinning de SDK externo** — não fixe versão de API de SDK sem compat layer + plano de migração; deixar o pin estagnado vira technical-debt time-bomb
- §56 **Webhook handlers — despachar o job, nunca processar inline** — o anti-padrão "`ProcessXJob` totalmente construído mas nunca despachado"; Stripe espera resposta ≤30s; retries silenciosos quando o handler estoura o timeout; `JsonResponse(['received' => true])` ANTES da lógica de negócio
- §57 **Token domain binding — cabeçalho ausente não é "dev mode"** — `detectDomain()` retornando `''` e listando `''` em `DEV_DOMAIN_HINTS` torna o binding contornável omitindo o header; fallback correto é o `Host` da requisição, e binding presente exige header presente
- §58 **Timestamps de migração devem ser únicos** — Laravel ordena por filesystem sort quando carimbos colidem (indefinido entre plataformas); antes do release, renomeie; depois do release, escreva uma migração de reparo idempotente
- §59 **Verificação HMAC deve devolver o modelo resolvido** — não re-consultar `Subscription`/`OrderItem` no controller depois que a camada de assinatura já fez o lookup; um endpoint público chamado a cada page load amplifica cada query duplicada por 100×
- §60 **End-to-end testing harness** — `tests/E2E/` reusável (PHPUnit + Python + Edge headless): matriz de endpoints com happy/falha, screenshots reproduzíveis, probe de latência do webhook, testes de regressão de findings sem boot do Flarum
- §61 **Traceable-conventions audit contract** — alternative output to §48: 18-convention checklist, Quality Score + Vibe Coded rubric, two canonical verdict phrases; report defaults to English with a PT-BR variant on explicit user request
- §62 **Multi-write atomicity & DB transactions** — every flow writing to ≥2 rows/tables (checkout, webhook, chained observer, sequential numbering) runs inside `Model::query()->getConnection()->transaction(...)`; webhook idempotency via `firstOrCreate` + unique `event_id`; no `DB` facade
- §63 **Request-derived state must be memoized** — the "phantom cart" bug: `scope()` minting a fresh random key on every call; memoize per `spl_object_id($request)`; never return an `id` from unconfirmed persistence
- §64 **Validate input SHAPE before semantic rules** — `array_column` silently returns `[]` on a malformed shape and skips every downstream validator; duplicate keys in a PHP array literal overwrite silently
- §65 **HTTP status & API surface symmetry** — 204 must not masquerade as soft-delete; a `create` response must compose into a read route that exists; 405-vs-404; probe every CRUD verb on every path
- §66 **One trigger per state-change effect** — Observer + service firing the same post-payment effect = double execution; split by a discriminating column (`stripe_session_id`); webhook re-entrant work is idempotent
- §67 **Error-handling completeness** — instrumented central API wrapper; every loading component has 3 states (`loading`/`error`/`data`); Mithril has no `componentDidCatch` (manual ErrorBoundary + `unhandledrejection`); `fetch()` checks `res.ok`; no empty PHP `catch`, no over-narrow catch type
- §68 **Debug/maintenance scripts never ship in the package** — `fix_db.php`, `view_logs.php`, `test_boot.php`, `enable_ext.php` in the extension root become unauthenticated webroot endpoints (DB-wipe, log disclosure, app boot); delete them; vendor third-party packages via `composer require`, never by copying their `src/`

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
- `Illuminate\Database\Capsule\Manager` used as a query entrypoint (`use Illuminate\Database\Capsule\Manager as DB; DB::table(...)`). It *works* because Flarum boots Capsule globally, but it's a convention smell — it reaches around Flarum's connection management and the static facade is fragile under tests and queue workers. Reference smell: [src/Api/ForumAttributes.php:35](src/Api/ForumAttributes.php#L35) and [:55](src/Api/ForumAttributes.php#L55).

**Preferred order for DB access** (mirror what first-party extensions do):
  1. **Eloquent model** (`Discussion::query()`, `User::query()`, your own `extends AbstractModel`). Always first choice — Flarum wires the connection, scopes, events, soft-deletes, and visibility traits for you. 95% of extension queries fit here.
  2. **Method-injected `Illuminate\Database\ConnectionResolverInterface`** when a controller/handler needs raw SQL across multiple connections, or genuine bulk inserts (`->table('x')->insertOrIgnore([...])` with thousands of rows where Eloquent's per-row hydration is wasteful).
  3. **Constructor-injected `Illuminate\Database\ConnectionInterface`** — last resort. Reviews flag direct `ConnectionInterface` constructor injection as a convention issue precisely because most of those cases were really Eloquent-shaped. Before adding `private ConnectionInterface $db` as a dependency, ask: would the class be cleaner with a model? Reference: a verification-style extension storing `verification_requests` rows had `UserResourceFields` and `ListApprovedUsersController` both injecting `ConnectionInterface` to count pending rows — an Eloquent `VerificationRequest` model with a `scopePending()` would eliminate both injections AND make the rest of §38.1 (N+1 fix via `with()`) trivial.
  4. **`Illuminate\Database\Capsule\Manager`** — never. Static facade, breaks under queue workers, hides the dependency.

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
rg -n "CURLOPT_SSL_VERIFYPEER|CURLOPT_SSL_VERIFYHOST|'verify'\\s*=>\\s*false|verify_peer'?\\s*=>\\s*false" src/
```

- URL fetched from user input MUST validate scheme AND resolved host:
  - Reject internal IPs: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16` (AWS metadata), `0.0.0.0/8`.
  - Reject IPv6 link-local (`fe80::/10`), unique-local (`fc00::/7`), loopback (`::1/128`).
  - Resolve DNS → IP, re-check the IP. Defeat DNS rebinding by pinning the resolved IP for the actual request.
- Disable `allow_url_fopen` if you pass user URLs to image libraries. Intervention\Image
  `make($url)` is a known SSRF vector (CVE-2023-40033 in Flarum core).

#### TLS verification — never disable

`CURLOPT_SSL_VERIFYPEER => false`, `CURLOPT_SSL_VERIFYHOST => 0`, or Guzzle
`'verify' => false` defeats certificate validation, opening every server-side fetch to
a network-positioned attacker (rogue WiFi, compromised egress proxy, malicious upstream
CDN). The "self-signed staging server" excuse should be solved with `'verify' =>
'/path/to/staging-ca-bundle.pem'`, not by disabling verification globally. Disabled
verification on a production extension is **🔴 critical** — promote to a release
blocker regardless of how minor the surrounding feature seems.

#### Response size cap — server-side

The client-side advice in the next subsection (streamed size cap) applies even harder
server-side: a malicious URL can serve a 5 GB body and OOM the worker. Cap with a
streaming buffer:

```php
// Guzzle — abort after N bytes
$client = new \GuzzleHttp\Client();
$body = '';
$maxBytes = 5 * 1024 * 1024;                            // 5 MB
$response = $client->request('GET', $url, [
    'stream'  => true,
    'timeout' => 10,
    'connect_timeout' => 5,
    'verify'  => true,
]);
$stream = $response->getBody();
while (! $stream->eof()) {
    $chunk = $stream->read(8192);
    $body .= $chunk;
    if (strlen($body) > $maxBytes) {
        $stream->close();
        throw new \RuntimeException('Response too large');
    }
}
```

For cURL: use `CURLOPT_PROGRESSFUNCTION` to abort when `$dlnow > $maxBytes` by
returning non-zero. `CURLOPT_NOPROGRESS` must be `false` to enable the callback.

#### URL normalization — case, encoding, IDN

A naive `parse_url($url)['host']` returns the host as the user supplied it. An
attacker can defeat a blocklist by varying:
- **Case**: `Localhost`, `LOCALHOST` — compare on `strtolower($host)` only after
  normalizing punycode.
- **Percent-encoding**: `loc%61lhost` — decode once with `rawurldecode` before checking.
- **IDN / punycode**: `xn--<lookalike>` decodes to a Unicode lookalike for an internal
  hostname. Use `idn_to_ascii($host, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46)` to
  canonicalize, then compare.
- **Trailing dot**: `localhost.` resolves to `localhost` on most resolvers but bypasses
  a string-equality block. Strip the trailing dot.
- **IPv6 brackets**: `[::1]` vs `::1` vs `0:0:0:0:0:0:0:1` — always parse with
  `inet_pton` and compare on the binary form.

```php
$host = parse_url($url, PHP_URL_HOST);
$host = rtrim(strtolower(rawurldecode((string) $host)), '.');
if (function_exists('idn_to_ascii')) {
    $host = idn_to_ascii($host, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46) ?: $host;
}
$resolved = gethostbynamel($host) ?: [];                // expand to all A records
foreach ($resolved as $ip) {
    if (! filter_var($ip, FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        throw new \RuntimeException('Resolved to a blocked range');
    }
}
```

Then **use the resolved IP as the connection target** (cURL `CURLOPT_RESOLVE`,
Guzzle `curl.options.CURLOPT_RESOLVE`) while keeping `Host: $host` in the request
header. This defeats DNS rebinding — the attacker can't have the second resolution
point at `127.0.0.1` because you never resolve again.

#### Authentication and rate limiting on outbound-fetch endpoints

Any endpoint that fetches a user-supplied URL on the server must:
1. Require authentication (`assertRegistered()` minimum; `assertCan('myext.fetchUrl')`
   if the feature is sensitive).
2. Apply a per-actor throttler (§18) — without one, an authenticated user can pin a
   worker on `Sleep` URLs and OOM the host on response-size limits.
3. NOT be exempted from CSRF (§16) — token-authenticated callers bypass CSRF by
   design, but a session-authenticated cross-site form post should be rejected.

A finding of "no authentication or rate limiting on outbound-fetch endpoints" is
**🔴 critical**: unauthenticated SSRF on a Flarum forum gives an attacker the forum's
egress IP to probe internal infrastructure, cloud metadata services
(`169.254.169.254`), and any service that allowlists the forum's IP.

#### Cache keys — scheme matters

A link-preview cache keyed by hostname/path but not scheme collides between
`http://example.com/x` and `https://example.com/x`. The plaintext response wins (or
the first to resolve wins), and the next visitor reading the HTTPS link gets
attacker-controlled plaintext content. Always include scheme + full normalized URL in
the cache key — see §24 for the cache-key shape.

```php
$key = 'myext.linkpreview.' . hash('sha256',
    $scheme . '://' . $host . $path . '?' . ($query ?? ''));
```

#### Synchronous DNS / fetch in the request path

Even after every SSRF mitigation, a `gethostbynamel()` or HTTP request in the
synchronous request thread blocks the worker for the duration. On a slow or
unreachable target, that's seconds-to-the-timeout per request — a DoS vector against
your own forum, no attacker needed. Push uncached fetches to a queued job
(`Extend\ServiceProvider` + a `Bus` dispatch) and return a "pending" placeholder. The
job runs in a queue worker, not a web worker — outage doesn't cascade to first paint.

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

**Binding an instance method as a listener.** `Extend\Event::listen($event, $listener)`
types `$listener` as `callable|string`. PHP's `callable` check rejects the array form
`[MyListener::class, 'handle']` at boot when `handle` is a non-static instance method
(it can't prove the method is callable without an instance). Two correct shapes:

```php
// Preferred — pass the class name; the container resolves it (full DI) and calls __invoke()
(new Extend\Event())->listen(Posted::class, NotifyOnPosted::class),

// For a named instance method, use Laravel's legacy 'Class@method' string —
// the dispatcher resolves it through the container at dispatch time (DI + instance method).
(new Extend\Event())->listen(Posted::class, NotifyOnPosted::class . '@handlePosted'),
```

Never inline a closure that needs dependencies — you lose container resolution.

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
- **A server-side sanitizer applied to some admin-HTML fields but not others.** An extension that ships an `HtmlSanitizer` class AND uses it for one admin-HTML surface, but registers another as `->serializeToForum('jsKey', 'ext.html_key')` with **no cast argument** — that second field ships raw in the forum payload and relies *solely* on a JS-side mirror at render time. Per §9.2 the allowlist must hold on **both** sides; a JS-only guard means any mXSS bypass (DOMParser blocklist sanitizers commonly miss `<svg>`/`<math>`/`<noscript>` foreign-content) is guest-visible XSS with no server-side backstop. The cast closure is the only place a sanitizer runs for `serializeToForum` output — wire it there: `->serializeToForum('jsKey', 'ext.html_key', fn ($html) => HtmlSanitizer::sanitize($html), '')`. Reference asymmetry: [src/Content/CustomLoadingSpinner.php:39](src/Content/CustomLoadingSpinner.php#L39) sanitizes its admin HTML server-side, but [extend.php:163](extend.php#L163) serializes `avocado.custom_hero_html` raw — same extension, same `HtmlSanitizer`, inconsistent application.
- **Admin-only operational settings serialized to every actor.** Retention windows (`*.retain_days`, `*.auto_delete_after`), purge thresholds, internal feature flags, and any "admin-tunable" knob that the forum frontend doesn't actually consume — these are payload weight + information disclosure for zero functional gain. Either keep them DB-only and read them server-side, or gate exposure to admins by checking `RequestUtil::getActor()->isAdmin()` inside a `Content` injector and emitting `window.__myextAdmin = { … }` only for them. See §38.4 for the size-conscious framing.
- **Large blobs in `serializeToForum`.** Anything that can grow past a few hundred bytes — base64 SVG (admin-uploaded badges up to 256 KB), rendered HTML hero, JSON snapshots — bloats every forum-page payload, every API response, every guest view. Even small per-extension blobs compound across 5–10 installed extensions. If the asset is fetched only on a specific route, expose it via a dedicated `ApiResource` field or a public URL — not the global forum payload. See §38.4.

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

**Prefer the `Flarum\Database\Migration` helpers** over raw `'up' => fn (Builder $schema)
=> $schema->create(...)` arrays. The helpers cover the common shapes (`createTable`,
`createTableIfNotExists`, `addColumns`, `dropColumns`, `renameColumn(s)`, `addSettings`,
`addPermissions`) and bring idempotency + portable down handlers for free:

```php
<?php

use Flarum\Database\Migration;
use Illuminate\Database\Schema\Blueprint;

return Migration::createTableIfNotExists('myext_items', function (Blueprint $table) {
    $table->id();
    $table->string('title', 100);
    $table->foreign('user_id')->references('id')->on('users')->cascadeOnDelete();
});

// Adding columns to an existing table. NOTE the `length` key — Laravel's
// addColumn() only reads NAMED options, so `['string', 20, ...]` silently
// loses the length and produces `varchar()` (invalid MySQL DDL).
return Migration::addColumns('myext_items', [
    'reviewed_at' => ['dateTime', 'nullable' => true],
    'priority'    => ['integer', 'default' => 0, 'after' => 'status'],
    'status'      => ['string',   'length' => 20, 'nullable' => true],
]);
```

The raw `'up' => fn (Builder $schema) => ...` form is still valid (Flarum accepts
both) but only worth it when the helper can't express the operation: dropping a
unique index alongside the column, data backfills, driver-gated raw SQL. For
everything else, the helper is the convention — newcomers recognise the shape and
the portability across MySQL/PostgreSQL/SQLite is enforced by Flarum itself.

### Critical pitfall — `length` must be a named key

```php
// BAD — `20` lands at index 0; addColumn() ignores numeric keys; MySQL gets
// `add `status` varchar() null` and the migration crashes at runtime.
'status' => ['string', 20, 'nullable' => true],

// GOOD — named key reaches the Blueprint as the column's length.
'status' => ['string', 'length' => 20, 'nullable' => true],
```

If the column needs precise control (decimal precision, enum values, raw type
expression), drop the helper for that one migration and use the raw closure
form below — don't try to bend the helper.

### Raw form (use only when the helper can't express it)

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

### GDPR / data export integration — full integration guide

If your extension persists ANY user-controlled data — uploads, drafts, preferences not
covered by core, audit rows, foreign-system identifiers, IP addresses, free-text
moderator-visible notes that the user authored — and `flarum/gdpr` is installed, you
**must** register a data type that handles **all three** lifecycle phases: export,
anonymize, delete. Missing any one is a GDPR violation:

| Phase | Right (GDPR article) | Failure mode |
|---|---|---|
| `export()` | Right of access (Art. 15) | User can't obtain their data |
| `anonymize()` | Right to rectification / restriction (Art. 16, 18) | User's identity persists in your tables after the core anonymization sweep |
| `delete()` | Right to erasure (Art. 17) | User's rows survive account deletion as orphans |

#### Composer wiring — `require` vs `suggest`

**Never `composer require flarum/gdpr`** from your extension `composer.json`. That makes
GDPR a hard install dependency on every forum, including those that don't care.
Instead:

```json
{
  "suggest": {
    "flarum/gdpr": "Required for data-export and erasure integration (^2.0)."
  }
}
```

…and **gate the wiring in `extend.php`** so the extension boots cleanly with or without
GDPR present:

```php
// extend.php
use Flarum\Extend;

$extenders = [
    // ... your normal extenders ...
];

if (class_exists(\Flarum\Gdpr\Extend\UserData::class)) {
    $extenders[] = (new \Flarum\Gdpr\Extend\UserData())
        ->addType(\Vendor\MyExt\Gdpr\MyData::class)
        ->removeUserColumns(['my_legacy_pii_column']);   // if you also wrote to users
}

return $extenders;
```

`class_exists` is the right gate (not `app(ExtensionManager::class)->isEnabled('flarum-gdpr')`)
— composer autoloading is finalized by the time `extend.php` is read, but Flarum's
extension manager state may not be. The `class_exists` check is cheap and
synchronously-decidable. A review finding flagging "GDPR Erasing event dependency not
declared" is satisfied by this gate plus the `composer.json` `suggest` entry.

#### Implementing the data type

The cleanest path is **extending `Flarum\Gdpr\Data\Type`** rather than implementing
`Flarum\Gdpr\Contracts\DataType` from scratch — the abstract base wires translator
keys, the disk factory, and the user/erasureRequest constructor for you:

```php
namespace Vendor\MyExt\Gdpr;

use Flarum\Gdpr\Data\Type;
use Illuminate\Support\Arr;
use Vendor\MyExt\Models\AuditEntry;

class MyData extends Type
{
    // --- Identity ----------------------------------------------------------

    public static function dataType(): string
    {
        return 'AuditEntries';                          // appears in the export UI
    }

    /**
     * Keys WITHIN this data type's serialized export/event payloads that contain PII.
     * Used by the GDPR module to redact fields when event payloads are forwarded
     * to a message broker. Declare every PII column you serialize.
     */
    public static function piiFields(): array
    {
        return ['ip_address', 'user_agent', 'free_text_note'];
    }

    // --- Export (Right of access, Art. 15) ---------------------------------

    public function export(): ?array
    {
        $rows = [];

        AuditEntry::query()
            ->where('user_id', $this->user->id)
            ->whereVisibleTo($this->user)               // §5 — never leak others' rows
            ->orderBy('created_at', 'asc')
            ->each(function (AuditEntry $entry) use (&$rows) {
                $rows[] = [
                    "audit/entry-{$entry->id}.json" => $this->encodeForExport(
                        Arr::only($entry->toArray(), [
                            'action', 'created_at',
                            'ip_address',                // user's own data — fine
                            'free_text_note',            // user authored it — fine
                            // NEVER include moderator_note: that belongs to the moderator
                        ])
                    ),
                ];
            });

        return $rows ?: null;                           // null = nothing to export, skip
    }

    // --- Anonymize (Right to restriction / Art. 18) ------------------------

    public function anonymize(): void
    {
        // The user row itself is renamed by Flarum\Gdpr\Data\User AFTER every other
        // type. Your job is to scrub THIS extension's PII so the user's audit trail
        // can no longer be traced back to them, while keeping the audit row's
        // existence (for forum integrity, moderation history, etc.).
        AuditEntry::query()
            ->where('user_id', $this->user->id)
            ->update([
                'ip_address'     => null,
                'user_agent'     => null,
                'free_text_note' => null,
            ]);
    }

    // --- Delete (Right to erasure / Art. 17) -------------------------------

    public function delete(): void
    {
        // True deletion. If you have FK cascades configured in your migration
        // (§26), this might already happen via the user-row delete — but
        // declaring it here is defense in depth in case the FK is ever dropped.
        AuditEntry::query()->where('user_id', $this->user->id)->delete();
    }
}
```

#### Translator keys (mandatory)

`Flarum\Gdpr\Data\Type` looks up its description strings as
`flarum-gdpr.lib.data.<lowercased-dataType()>.{export,anonymize,delete}_description`.
**These keys must exist in your locale or the admin UI shows raw translation keys.**

```yaml
# locale/en.yml
flarum-gdpr:
  lib:
    data:
      auditentries:                              # lowercase of dataType()
        export_description: "Every audit log entry generated by your account, including the IP and free-text notes."
        anonymize_description: "IP address, user-agent, and free-text notes will be cleared on each audit entry. The entry itself is retained for forum integrity."
        delete_description: "Every audit entry attributed to your account is permanently deleted."
```

**Gotcha**: when the subclass does **not** override `dataType()`, the default
implementation in `Flarum\Gdpr\Data\Type` returns the short class name
(`Str::afterLast(static::class, '\\')`). A class named `MarketplaceUserData`
ships keys under `flarum-gdpr.lib.data.marketplaceuserdata.*` — not under your
extension's namespace. Easy to miss because grep for the key inside your
extension's `locale/<lang>.yml` returns nothing until you add the second root.

The yaml file ends up with TWO root keys side by side:

```yaml
ramon-marketplace:
  forum: { ... }
  admin: { ... }

flarum-gdpr:
  lib:
    data:
      marketplaceuserdata:
        export_description: "..."
        anonymize_description: "..."
        delete_description: "..."
```

YAML supports multiple top-level documents — both roots resolve via the
extension's `Extend\Locales(__DIR__.'/locale')` registration.

If your data type's `anonymize` and `delete` produce the same result, follow the
`Discussions` pattern — override `anonymizeDescription()` to call `deleteDescription()`
and have one locale key.

#### `removeUserColumns` — opting columns out of the `Data\User` export

If your extension added columns directly to the `users` table (you shouldn't — see §45
— but if you inherited an extension that did), those columns are picked up by
`Flarum\Gdpr\Data\User::export()` automatically. Use `removeUserColumns` to suppress
columns the user shouldn't see in their own export (e.g., internal moderator-only flags
that happen to live on the user row):

```php
(new \Flarum\Gdpr\Extend\UserData())
    ->addType(MyData::class)
    ->removeUserColumns(['my_internal_flag', 'my_moderator_score']);
```

For ones that ARE user-owned, leave them in the export but list them in `piiFields()`
on a dedicated type so they're correctly redacted in serialized event payloads.

#### Type ordering — `Data\User` runs LAST, by design

`DataProcessor::addType` always re-inserts `Flarum\Gdpr\Data\User::class` at the end of
the type list. The reason: the User type **renames** the user (`username = "Anonymous{id}"`),
nulls the email, and clears preferences. Every preceding type's `anonymize()` runs
with the **original** username/email still on `$this->user`, which is usually what you
want (e.g., emailing the user a confirmation BEFORE rename). Don't rely on a specific
ordering between your type and another third-party type — order between non-User types
is registration order, and the next ext install can shuffle it.

#### Reservedabilities — keeping specific actions valid on anonymized users

Once a user is anonymized, `Flarum\Gdpr\Access\UserPolicy::can` **denies every ability**
against the anonymized user by default (vendor/flarum/gdpr/src/Access/UserPolicy.php:27).
Core preserves only `delete` via the `gdpr.user.reservedAbilities` container binding.
If your extension defines abilities that must still work post-anonymization (e.g.,
`moderator.canReadAuditLog` so audit history stays viewable), extend the binding from
**a service provider** registered via `Extend\ServiceProvider`:

```php
class MyExtGdprIntegrationProvider extends AbstractServiceProvider
{
    public function register(): void
    {
        if (! $this->container->bound('gdpr.user.reservedAbilities')) {
            return;                                    // gdpr not installed, no-op
        }
        $this->container->extend('gdpr.user.reservedAbilities', function (array $abilities) {
            return array_merge($abilities, ['myext.readAuditTrail']);
        });
    }
}
```

#### `Erasing` / `Erased` events for chained extension cleanup

For work that doesn't fit a `DataType` (cache invalidation, queue tear-down, external
SaaS notification), listen to `Flarum\Gdpr\Events\Erasing` (fires before the
DataProcessor pipeline) and `Flarum\Gdpr\Events\Erased` (fires after the user row has
been deleted or renamed):

```php
// extend.php — wrapped in class_exists gate as above
$extenders[] = (new Extend\Event())
    ->listen(\Flarum\Gdpr\Events\Erased::class, OnUserErased::class);
```

Note the **`Erasing` event carries an `ErasureRequest`**, not a `User` — the user model
on the request is unanonymized at this point. The **`Erased` event carries the User
plus the pre-anonymization username, email, and mode** (anonymization vs deletion) as
separate scalar properties. Read those, don't re-read `$user->username` — by the time
your listener runs, it's already `Anonymous{id}`.

#### Capability-URL caveat for downstream exports

If your data type produces a downloadable artifact distinct from the main ZIP (rare,
but happens for very large datasets), DO NOT roll your own download endpoint that
authenticates "via the random URL". Reuse the GDPR `Export` model so it inherits the
existing `ExportController` policy (capability-URL model — see §13.8) or write a
`ConfirmErasureController`-style endpoint that actually verifies the actor.

#### Final GDPR checklist for the extension

- [ ] `composer.json` lists `flarum/gdpr` under `suggest`, not `require`.
- [ ] `extend.php` wraps the `UserData` extender in `class_exists(\Flarum\Gdpr\Extend\UserData::class)`.
- [ ] Data type extends `Flarum\Gdpr\Data\Type` (or implements `DataType` with the full eight-method contract).
- [ ] `piiFields()` lists EVERY serialized key that contains PII (not just columns — also array keys produced inside `export()`).
- [ ] `export()` uses `->where('user_id', $this->user->id)` AND `->whereVisibleTo($this->user)` AND `->where('is_private', false)` where the model has those columns.
- [ ] `export()` never includes moderator-authored notes about the user.
- [ ] `anonymize()` clears every PII column listed in `piiFields()`.
- [ ] `delete()` actually deletes (FK cascade is not enough — declare it explicitly).
- [ ] Locale keys exist for `export_description`, `anonymize_description`, `delete_description`.
- [ ] If you preserved any ability post-anonymization, it's wired via `$container->extend('gdpr.user.reservedAbilities', ...)` inside a `bound()` check.
- [ ] Listeners for `Erased` read the pre-anonymization username/email from the event's scalar properties, never from `$user`.
- [ ] Capability URLs (random-filename downloads) reuse `Flarum\Gdpr\Models\Export` rather than rolling a parallel mechanism.

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

### The "acknowledged no-op" anti-pattern

A class left in `src/` with a comment — in `extend.php` or the class itself — that says
something like *"remains as a no-op until removed in a future cleanup"* is still dead
weight: it's autoloaded, it surfaces in greps, and it makes the next reader stop to work
out whether it's wired. "Future cleanup" reliably never happens. **The PR that unwires a
class is the PR that deletes its file** — they are the same change. If you're not ready
to delete it, don't unwire it. Reference: [extend.php:32](extend.php#L32) comments
`DeferMainCss` out of the `content()` chain, but
[src/Content/DeferMainCss.php](src/Content/DeferMainCss.php) is still in the tree.

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
- [ ] `Content` injectors (`Extend\Frontend->content()`) check their enable/visibility setting first, bound every query (`limit()`), apply per-actor visibility, JSON_HEX-encode any user-controlled data put into `$document->head[]`/`foot[]`, and don't duplicate a query already served by an `ApiResource` field (§37).
- [ ] No `Illuminate\Database\Capsule\Manager` (`DB::table(...)`) as a query entrypoint — prefer an Eloquent model; constructor-injected `ConnectionInterface` is the last resort (§10, §39.3).
- [ ] No `Schema\*->get(fn ...)` callback runs a per-row query (N+1). Use `eagerLoad`, a denormalized column, or `withCount` instead (§38.1).
- [ ] Multi-column `WHERE a=? AND b=?` patterns are backed by a compound index in a migration (§38.3).
- [ ] No `serializeToForum(...)` ships a blob > ~4 KB or an admin-only operational setting to every actor (§21, §38.4).
- [ ] No controller builds a response by `file_get_contents` + `base64_encode` of a file — stream it via `Laminas\Diactoros\Stream` (§38.2).
- [ ] No `Model::query()->get()->filter(...)` where the filter could be a SQL `where()` (§38.5).
- [ ] Helper logic referenced from both a Schema getter and a controller lives on the model (accessor/method), not duplicated (§38.6).

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
- [ ] No `exec`/`shell_exec`/`system`/`passthru`/`proc_open`/`popen`/backticks with a user-influenced binary, flag, or unescaped argument; external-binary calls pin an absolute path, escape every argument (prefer the array form of `proc_open` — no shell), guard against `-`-prefixed argument injection, set a timeout, and check the exit code (§36).
- [ ] Untrusted media fed to ImageMagick/FFmpeg is constrained (`policy.xml` / `-protocol_whitelist file`) or processed via a library binding instead of the CLI (§36).
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
- [ ] A shipped HTML-sanitizer class is actually wired into the `serializeToForum` cast closure — not left as unreferenced dead code (§21).
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
- [ ] Every `JSON.parse(...)` / `await response.json()` wrapped in try/catch with a user-visible error path (§40.1).
- [ ] Every `.catch` / `try/catch` around an async call surfaces a `app.alerts.show({type:'error'}, …)` — no silent swallow (§40.2).
- [ ] No `document.querySelector` / `document.getElementsByClassName` on a class that multiple component instances render — scope to `this.element` (§40.3).
- [ ] No `as any` cast that hides a real type — augment the module instead (§40.4).
- [ ] Modern CSS (`color-mix`, `:has`, `oklch`) has a `@supports`-guarded fallback when used on extensions targeting Flarum 1.x (§40.5).
- [ ] Hardcoded list truncation (e.g. `.slice(0, 500)`) surfaces a count to the user — never silent (§40.6).
- [ ] Helper functions appearing in 2+ component files are extracted to `js/src/common/utils/` (§40.7).
- [ ] No `.less`/`.css` rule targets a class name that no JS/PHP emits (§40.8).
- [ ] `tsc --noEmit` (TS projects) passes; `webpack --mode production` passes.
- [ ] `js/dist/{forum,admin}.js` regenerated and committed.

### Compatibility & portability

- [ ] `composer.json` `"flarum/core"` constraint matches the API surface in `src/` — v2-only classes (`Flarum\Api\Resource\AbstractDatabaseResource`, `Flarum\Api\Schema\*`, `Flarum\Api\Endpoint\*`) require `"^2.0"` with no `^1.0` clause (§39.1).
- [ ] No `INFORMATION_SCHEMA` / `RAND()` / `FROM_UNIXTIME` / `GROUP_CONCAT` / MyISAM-specific DDL in migrations — Schema Builder is portable across MySQL/PostgreSQL/SQLite (§39.2).
- [ ] Composer `require` constraints on sister extensions (e.g. `flarum/tags`) are version-bounded — not `"*"` / unconstrained.

### Logging

- [ ] No `use Illuminate\Support\Facades\Log` — inject `Psr\Log\LoggerInterface` instead (§41).
- [ ] Logged context never includes request body, headers, tokens, or secrets (§23 + §41).

### Migration & cleanup

- [ ] Migration is idempotent (`hasTable`/`hasColumn` guards).
- [ ] Migration has a working `down` OR documents why rollback is impossible.
- [ ] If a setting/column was removed, the migration deletes its persisted rows.
- [ ] Locale entries added for every visible string AND every custom permission ability.
- [ ] No `// removed`/`// legacy` comments left on dead code, no `.less` block for a feature whose JS/PHP doesn't ship.
- [ ] No `Schema::table('users'/'discussions'/'posts'/'discussion_user'/'groups'/'tags')` — all extension data is on a companion table with a FK back to the core row (§45).

### Project hygiene & scaffolding (§42)

- [ ] `extend.php` delivers concrete, non-skeleton functionality (routes, models, resources, schema fields).
- [ ] No `console.log` / `console.debug` / `debugger;` in `js/dist/{forum,admin}.js`.
- [ ] `composer.json` `extra.flarum-extension.title/category/icon` are the extension's real values, not `flagrow.*` / `reflar.*` / placeholder text.
- [ ] Every path referenced from `extend.php` (`__DIR__.'/locale'`, `__DIR__.'/js/dist/...'`, `__DIR__.'/resources/...'`) exists and is non-empty.
- [ ] `locale/en.yml` is non-empty and contains a key per visible translator slug.
- [ ] PHPStan (and any other lint step) in CI is either blocking or removed — no `continue-on-error: true` on quality gates.

### Composer & integration contracts (§43)

- [ ] `"flarum/core"` constraint matches the API surface actually imported in `src/` (§39.1).
- [ ] No `"flarum/<sister>": "*"` unbounded constraint.
- [ ] Optional integrations are in `suggest`, not `require`; their `extend.php` wiring is wrapped in `class_exists(...)`.
- [ ] Container `bound('<key>')` check precedes any `resolve(...)` / `$container->extend('<key>', ...)` for an optional binding (§44.3).
- [ ] `"php": "^8.2"` (or stricter) constraint matches the CI matrix and Flarum 2.x baseline.

### Long-lived process safety (§44)

- [ ] `set_error_handler` / `set_exception_handler` calls capture the previous handler and call it from the new one.
- [ ] No `protected static $foo` cache on Eloquent models holding actor- or request-scoped data.
- [ ] No `resolve('key')` / `app('key')` on an extension-provided key without `$container->bound('key')` first.
- [ ] Singletons registered via `Extend\ServiceProvider` never hold request-scoped state.

### Polymorphic subjects & notifications (§46)

- [ ] Every `Blueprint` constructor uses typed parameters; the typed model is the one returned by `getSubject()`.
- [ ] `getType()` string is declared as a class constant; the frontend reads it via `app.forum.attribute(...)` or a constant — not a duplicated literal.
- [ ] `beforeSending` recipient filter re-checks `$user->can('view', $blueprint->subject)` for any blueprint whose subject has visibility rules.
- [ ] `getData()` returns IDs and primitive scalars only — never raw user content.
- [ ] Event listeners that wrap another extension's event read pre-anonymization scalars from the event properties, not from `$user->username` after the fact.

### Admin-controlled execution surfaces (§47)

- [ ] No `createContextualFragment` / `new Function` / `eval` consuming an admin setting value.
- [ ] No `innerHTML = settingValue` outside a sanitized pipeline; `style.innerHTML` interpolation is replaced with `style.textContent` + regex-validated values.
- [ ] Shipped HTML-sanitizer classes are wired into the `serializeToForum` cast closure — not orphaned in `src/Support/`.
- [ ] Custom-JS/HTML settings expose a visible warning banner in the admin UI and require a dedicated ability (not just `administrate`).

### GDPR integration (§30, when `flarum/gdpr` is involved)

- [ ] `flarum/gdpr` is in `suggest`, not `require` (unless the extension is genuinely useless without it).
- [ ] `Extend\UserData` wiring is wrapped in `class_exists(\Flarum\Gdpr\Extend\UserData::class)`.
- [ ] Data type extends `Flarum\Gdpr\Data\Type` and implements `dataType()`, `piiFields()`, `export()`, `anonymize()`, `delete()`.
- [ ] `export()` filters by `user_id` AND `whereVisibleTo($user)` AND, where applicable, `is_private = false`.
- [ ] Locale keys `flarum-gdpr.lib.data.<lowercased-type>.{export,anonymize,delete}_description` exist.
- [ ] `gdpr.user.reservedAbilities` extension is wrapped in `$container->bound(...)`.

### Atomicity, request state, API surface (§62–§66)

- [ ] Every handler/observer/job with 2+ writes is wrapped in `Model::query()->getConnection()->transaction(...)` — not the `DB` facade (§62).
- [ ] Webhook fulfillment is idempotent: unique `event_id` guard before the transaction, `firstOrCreate` for re-delivery-duplicable rows (§62).
- [ ] Sequential numbering (`*_number`) uses `lockForUpdate()` inside a transaction (§62).
- [ ] No request-derived identifier (session key, scope hash) is recomputed from `random_bytes`/`uniqid` on each call — memoized per `spl_object_id($request)` (§63).
- [ ] No response returns an `id` before persistence is confirmed (§63).
- [ ] Input *shape* is validated before any semantic rule — no `array_column`/`Arr::pluck` on an unvalidated body (§64).
- [ ] No duplicate keys in any array literal / `->map()` item (§64).
- [ ] No `204` masquerading as soft-delete; every `create` response composes into a working `GET /{id}`; every CRUD verb probed against every path (§65).
- [ ] Every state-change effect has exactly one trigger per origin; Observer vs service mutually exclusive via a discriminating column (§66).

### Error-handling completeness (§67)

- [ ] Central API wrapper attaches a `.catch()` that alerts on 5xx/network and re-throws.
- [ ] Every data-loading component has `loading` + `error` + `data` and renders all three.
- [ ] `ErrorBoundary` per route/page + global `unhandledrejection` listener in both `index.tsx` files.
- [ ] Every `fetch()` checks `res.ok`.
- [ ] No empty PHP `catch`; no over-narrow catch type letting siblings escape to a 500; no `@`-suppressed I/O without a return-value check.

### Hygiene — no debug scripts shipped (§68)

- [ ] No `.php` in the extension root other than `extend.php` (no `fix_db.php`, `view_logs.php`, `test_boot.php`, `enable_ext.php`).
- [ ] No third-party package vendored by copying its `src/` — declared via `composer require` instead.
- [ ] No Laravel-Framework helpers (`response()->`, `public_path()`, `view()`, `redirect()`) in `src/` — they don't exist in Flarum.

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

## §36. Shell command execution & external binaries

**CWE-78.** Flarum core never shells out. The moment an extension calls `exec`,
`shell_exec`, `system`, `passthru`, `proc_open`, `popen`, or backticks, it owns a
**command-execution surface**. Even when the immediate arguments are escaped, the binary
path, its flags, the working directory, the environment, and **the content of any file
passed in** are all part of the attack surface. CVE-2023-40033 (Intervention\Image
fetched a URL from a user-controlled string) and the ImageTragick class (CVE-2016-3714)
are the canonical "media tool processed untrusted input" incidents.

### Locate

```bash
rg -n "exec\\(|shell_exec|proc_open|passthru|system\\(|popen\\(" src/
rg -n "escapeshellarg|escapeshellcmd" src/
```

### Red flags

- **`escapeshellcmd` used instead of `escapeshellarg`.** `escapeshellcmd` escapes a whole command string and still lets an attacker inject extra arguments; `escapeshellarg` quotes exactly one argument. Always `escapeshellarg` each argument individually.
- **Argument injection.** `escapeshellarg` stops shell metacharacters, NOT a value that *is* a valid flag. A user value of `--output=/var/www/public/index.php` is one safe shell token but a dangerous CLI flag. Validate the value, place untrusted values only *after* a `--` separator, or pin them to a non-flag shape (`(int)` cast, allowlist).
- **Binary resolved via `$PATH`** (`ffmpeg`, `convert`) instead of an absolute, configured path — a poisoned `PATH` or a same-named binary in the CWD hijacks the call.
- **The binary name, a flag, or a format string comes from request/setting input.** The only thing that may come from input is a *quoted value argument*, and only after validation.
- **`2>/dev/null` hardcoded** — POSIX-only; under cmd.exe (`exec` on Windows — and this repo develops on Windows) it redirects to a literal `dev\null` path. It also swallows stderr, hiding the real failure. Capture stderr via `proc_open` pipes instead.
- **No timeout.** `exec` blocks until the child exits. A crafted GIF/video can pin FFmpeg at 100% CPU indefinitely (DoS). Use `proc_open` + a wall-clock deadline, or a `timeout(1)` wrapper.
- **Exit code unchecked** — always test `$code !== 0` *and* verify the expected output file exists and is non-empty.
- **Untrusted file content fed to a media tool.** Even with a perfectly escaped command line, ImageMagick follows `MSL`/`MVG`/`HTTPS` directives and FFmpeg's `concat`/`hls` demuxers read `file://`/`http://` from inside a crafted input — SSRF / LFI with no shell involved. Mitigate: an ImageMagick `policy.xml` that disables non-image coders, `-protocol_whitelist file` on FFmpeg, or drop the binary for a library binding (`ext-imagick`, `ext-gd`, `php-ffmpeg`) which exposes a typed API instead of a string.

### Correct shape

```php
// Pin the binary, pass arguments as an array (no shell → no escaping needed),
// run under a timeout, check the exit code AND the output.
$ffmpeg = '/usr/bin/ffmpeg';                          // absolute, not $PATH
if (! is_executable($ffmpeg)) {
    throw new RuntimeException('ffmpeg not available');
}

$descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
$proc = proc_open(
    [
        $ffmpeg,
        '-protocol_whitelist', 'file',                // block concat/hls SSRF
        '-i', $src,                                   // $src = server-generated temp path
        '-c:v', 'libx264', '-pix_fmt', 'yuv420p',
        '-preset', 'fast', '-crf', '28',
        $out,                                         // $out = server-generated temp path
    ],
    $descriptors, $pipes
);                                                    // array form — no shell involved at all

if (! is_resource($proc)) throw new RuntimeException('ffmpeg failed to start');

$deadline = microtime(true) + 30;                     // hard wall-clock cap
while (proc_get_status($proc)['running']) {
    if (microtime(true) > $deadline) {
        proc_terminate($proc, 9);
        throw new RuntimeException('ffmpeg timed out');
    }
    usleep(50_000);
}
$code = proc_close($proc);
if ($code !== 0 || ! is_file($out) || filesize($out) === 0) {
    throw new RuntimeException('ffmpeg conversion failed');
}
```

The **array form of `proc_open`** (PHP 7.4+) bypasses the shell entirely — there is no
string to escape, so argument injection via metacharacters is structurally impossible.
Prefer it over `exec(sprintf(...))` for every new call. If you must keep `exec`:
`exec(sprintf('%s -i %s %s', escapeshellarg($bin), escapeshellarg($src), escapeshellarg($out)), $o, $code)`
— every token `escapeshellarg`'d, the binary included, a constant flag set in between.

### Reference (this extension)

[src/Controller/OptimizeImageController.php:231](src/Controller/OptimizeImageController.php#L231)
and [:261](src/Controller/OptimizeImageController.php#L261) shell out to `ffmpeg` and
`convert`. They do the hard parts right — admin-only (`assertAdmin()`), SSRF-validated
input URL, DNS-pinned download, MIME-sniffed content, `escapeshellarg` on every path.
Remaining hardening, in severity order: (1) the input file is admin-supplied remote
content fed straight to ImageMagick/FFmpeg → add `-protocol_whitelist file` + an
ImageMagick `policy.xml`, or move to `ext-imagick`; (2) no timeout → a crafted file
hangs the worker; (3) `2>/dev/null` is POSIX-only and this repo develops on Windows;
(4) `ffmpeg`/`convert` resolve via `$PATH` — pin absolute paths or make them a setting.
Severity is **🟠 medium**, not high: exploitation needs a compromised admin account, but
the blast radius if reached is RCE-adjacent — treat it as the extension's sharpest edge.

---

## §37. Frontend `Content` injectors (`Extend\Frontend->content()`)

`Extend\Frontend('forum')->content(fn (Document $document, ServerRequestInterface $request) => …)`
runs **server-side, synchronously, on every full (non-SPA) page load**, before the HTML
is flushed. It's the right tool for above-the-fold data and `<head>` tags — and a
recurring source of three bugs: raw-HTML XSS, per-page query cost, and silent
duplication of an `ApiResource` field.

### Locate

```bash
rg -n "->content\\(" extend.php
rg -n "document->head\\[\\]|document->foot\\[\\]" src/
```

### Red flags

- **`$document->head[] = '...' . $userControlled . '...'`** — the `head`/`foot` arrays are emitted as **raw HTML**; Mithril/Blade escaping does not apply here. Any user-controlled value (username, display name with a nickname extension installed, free-text setting) must be JSON-encoded with `JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT` before interpolation into a `<script>`, or `htmlspecialchars`'d before interpolation into markup. A bare `json_encode($x)` is **not** enough — `</script>` / `</style>` break out of the element.
- **A query inside a `Content` injector that is also computed by an `ApiResource` field.** The injector runs for the SSR payload; the resource runs for the API response the SPA fetches milliseconds later. Same data, two queries, every page load. Pick one source of truth — either the SSR injector (and have the JS read `window.__x` instead of refetching) or the API field (and accept the first-paint round-trip), not both.
- **An injector that does work before checking its enable/visibility setting.** It runs on *every* page; an unconditional `User::where(...)->get()` is a per-request cost paid even when the feature is off.
- **Per-actor data injected without the per-actor check.** `Document` is built for the requesting actor, but it's easy to inject something they shouldn't see (online users who set `discloseOnline = false`, counts of restricted-tag discussions). Re-apply the same visibility filter the API resource would.
- **Expensive or unbounded work** — no `limit()`, an N+1 over a relation, an external HTTP call — all of it lands on the critical path of first paint.

### Correct shape

```php
public function __invoke(Document $document, ServerRequestInterface $request): void
{
    if (! $this->settings->get('myext.feature_enabled', false)) {
        $document->head[] = '<script>window.__myextData=[];</script>';   // cheap early-out
        return;
    }

    $data = User::select(['id', 'username', 'avatar_url', 'preferences'])
        ->where('last_seen_at', '>=', Carbon::now()->subMinutes(5))
        ->limit(50)                                                       // always bounded
        ->get()
        ->filter(fn (User $u) => $u->preferences['discloseOnline'] ?? true) // per-actor visibility
        ->map(fn (User $u) => ['id' => $u->id, 'username' => $u->username])
        ->values()->toArray();

    // JSON_HEX_* prevents `</script>` / quote break-out from user-controlled fields.
    $json = json_encode($data,
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
        | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);

    $document->head[] = "<script>window.__myextData={$json};</script>";
}
```

### Reference (this extension)

[src/Content/InjectOnlineUsers.php:49](src/Content/InjectOnlineUsers.php#L49) is the
**correct** `<head>` injection pattern — bounded query, `discloseOnline` filter, and the
full `JSON_HEX_*` flag set. Copy it. The gap is duplication:
[src/Api/ForumAttributes.php:62](src/Api/ForumAttributes.php#L62) computes the *same*
online-user list as an `avocadoOnlineUsers` API attribute, so every forum page runs the
query twice. Resolve by deleting one side — keep the SSR injector and have the JS read
`window.__avocadoOnlineUsers`, or keep the API field and drop the injector.

---

## §38. Performance, memory, and N+1 patterns

Security review will flag exploitable bugs; performance review will flag the bugs that
make the forum unusable at scale. **Reviewers grade an extension lower for one
unbounded query on a hot path than for a closed-off admin-only RCE primitive** — the
unbounded query degrades every page load for every actor. This section catalogs the
five recurring shapes that have shown up across recent reviews.

### 38.1 N+1 in Schema field `->get()` callbacks

A `Schema\*::make(...)->get(fn (User $user, Context $ctx) => …)` callback runs **per
row** in the response. On a 50-row admin user listing, one DB query inside the
callback = 50 queries; with two such fields, 100. The reviewer who flagged
`hasPendingVerificationRequest` on a verification extension wasn't wrong to call this
"the worst pattern in the file" — it's invisible in code review (looks like one field)
but quadratic at runtime.

**Locate**:

```bash
rg -n "Schema\\\\(Str|Boolean|Integer|Arr|Number)::make.*->get\\(" src/
```

For each hit, ask: does the closure call `->where()`, `->first()`, `->count()`, or
touch a relation that wasn't eager-loaded? If yes, it's an N+1.

**Three correct shapes, in order of preference**:

1. **Eager-load the relation** in a `ListResource`-style `eagerLoad` hook (Flarum v2 has
   `Endpoint\Index::make()->eagerLoad('verificationRequests')`). Then the `get` closure
   reads `$user->verificationRequests->isNotEmpty()` — no extra query.
2. **Use a database column** instead of a derived flag. Maintain `users.has_pending_verification` via an Eloquent observer on `VerificationRequest::saved/deleted`. Trade write cost (1 update per state change) for read cost (N queries per listing) — almost always the right trade.
3. **Use a `withCount` or `whereHas` on the parent query** so the count comes back as a column on the user row, then read `$user->verification_requests_count > 0` in the closure.

**Anti-pattern (verification extension, paraphrased)**:

```php
// src/Api/UserResourceFields.php — runs ONE query per user row
Schema\Boolean::make('hasPendingVerificationRequest')
    ->get(function (User $user) {
        return $this->db->table('verification_requests')
            ->where('user_id', $user->id)
            ->where('status', 'pending')
            ->exists();                                          // ← N+1
    }),
```

**Correct shape**:

```php
// 1. Add an Eloquent relation on User (via Extend\Model)
(new Extend\Model(User::class))
    ->hasMany('verificationRequests', VerificationRequest::class, 'user_id'),

// 2. Eager-load on the listing endpoint
Endpoint\Index::make()
    ->can('administrate')
    ->eagerLoad('verificationRequests'),

// 3. Read the loaded collection — no extra query
Schema\Boolean::make('hasPendingVerificationRequest')
    ->get(fn (User $user) =>
        $user->verificationRequests->contains(fn ($r) => $r->status === 'pending')
    ),
```

The same fix dissolves the §10 "direct `ConnectionInterface` injection" smell: once
`VerificationRequest` is a model with a `scopePending()`, neither the schema field nor
the controller needs `$this->db` at all.

### 38.2 Buffering full responses into PHP memory

A controller that builds an export, reads the whole file with
`file_get_contents`/`base64_encode`, then returns the string in a `Response` will
**double-or-triple the file size in resident PHP memory**. On `memory_limit = 128M`
(common shared-host default) and a 60 MB ZIP, the request hits OOM with a fatal error.
Reviewers see this and rate the extension high-risk regardless of how clean the
authorization is.

**Locate**:

```bash
rg -n "base64_encode\\(file_get_contents|->getContents\\(\\)\\s*\\)|file_get_contents.*\\.zip" src/
rg -n "->get\\(\\)\\s*->filter\\(|->all\\(\\)\\s*->filter\\(" src/   # PHP-side filter of full set
```

**Anti-patterns**:

```php
// Anti-pattern 1: base64 the whole file just to ship it
$zipBytes = file_get_contents($zipPath);
return new JsonResponse([
    'filename' => 'stickers.zip',
    'content'  => base64_encode($zipBytes),                      // ← 4 MB on disk → 16 MB in memory (orig + base64 + JSON-encoded)
]);

// Anti-pattern 2: load everything into memory to filter a subset
$users = User::query()->where('approved', true)->get();          // ← 50k rows
$tier1 = $users->filter(fn (User $u) => $u->tier_id === 1);      // ← PHP-side filter
return new JsonResponse($tier1->take(20)->toArray());
```

**Correct shapes**:

```php
// Stream the file as an octet-stream response
return new Response(
    new \Laminas\Diactoros\Stream($zipPath, 'rb'),               // ← streaming, constant memory
    200,
    [
        'Content-Type'        => 'application/zip',
        'Content-Length'      => (string) filesize($zipPath),
        'Content-Disposition' => 'attachment; filename="export.zip"',
    ]
);

// Push filtering and pagination into the DB
User::query()
    ->where('approved', true)
    ->where('tier_id', 1)                                        // ← SQL WHERE
    ->orderBy('id')
    ->limit(20)
    ->get();
```

If the export format requires JSON-with-base64 (a frontend constraint you can't change
right now), accept the design but **cap the input** so the worst-case never OOMs: refuse
exports > N rows or > M MB on disk, return `413 Payload Too Large`, and document the
limit.

### 38.3 Missing compound indexes on multi-column WHERE

A query that filters on two columns scans the table unless there's a compound index
covering both. Single-column indexes don't compose — MySQL uses one per table per query.

**Locate**:

```bash
rg -n "->where\\(.*->where\\(" src/         # chained where on same query
rg -n "WHERE.*AND.*=" migrations/           # migrations that don't add a compound index
```

Then cross-reference each `WHERE a=? AND b=?` pattern against the migration's `$table->index([...])` calls. Single-column `$table->index('user_id')` does NOT cover `WHERE user_id=? AND status=?`.

**Correct shape**:

```php
// In the migration that creates `verification_requests`
$table->index(['user_id', 'status'], 'verification_requests_user_status_idx');

// In a follow-up migration if the table already exists in production
Schema::table('verification_requests', function (Blueprint $table) {
    $table->index(['user_id', 'status'], 'verification_requests_user_status_idx');
});
```

The order in the compound index matters: put the higher-cardinality column first
(`user_id` usually, since `status` only has a handful of distinct values). For a query
that filters by `status` first and `user_id` second, you'd need a different ordering or
a second index — though the same table almost never needs both.

### 38.4 Large blobs in `serializeToForum`

`->serializeToForum(...)` ships the value in **every** forum-page bootstrap payload,
**every** API root response, and **every** SPA reload. A 256 KB SVG (admin-uploaded
badge) means 256 KB × every page view × every actor. On a community doing 100k page
views/day this is **25 GB/day** of bandwidth for a single decorative asset, and it
adds ~50 ms of parse time to every initial paint on slow mobile connections.

**Locate**:

```bash
rg -n "serializeToForum\\(" extend.php src/
```

For each hit, ask:
1. Is the value a small scalar/boolean/short string? → fine.
2. Is it user-controlled or admin-controlled HTML/SVG/JSON? → §21 covers sanitization; here ask **how big can it get?** If unbounded or > 4 KB, **don't `serializeToForum` it**.
3. Is it consumed only by one route? → expose via that route's `ApiResource` field, not the global payload.

**Correct shape for admin-uploaded SVG badges**:

```php
// BAD — entire SVG in every forum-page payload
->serializeToForum('verifiedBadgeSvg', 'verified.badge_svg', null, '')

// GOOD — serve via a dedicated public URL and ship only the URL
(new Extend\Routes('forum'))
    ->get('/ext/verified/badge.svg', 'verified.badge', BadgeController::class);

// Then in the resource that needs it:
Schema\Str::make('verifiedBadgeUrl')
    ->get(fn () => $this->url->to('forum')->route('verified.badge'))
```

The SVG is cached by the browser, served with `Cache-Control: public, max-age=31536000`,
and the forum-page payload stays small. **Trade**: one extra HTTP request per fresh
visitor; for a 256 KB asset that's a clear win.

### 38.5 PHP-side filtering of full result sets

If a query returns all matching rows just to drop most of them in PHP, the query is
wrong. Push the filter into SQL with `where()`, `whereIn()`, or a proper
relationship-based `whereHas()`. Reviewers flag this as low severity — the worst case
is "slow", not "broken" — but it compounds with §38.1 N+1 and §38.2 buffering when
they appear together.

**Common shape**:

```php
// Anti-pattern (tier filter from a verification-style extension)
$users = User::query()->get();                                   // 50k rows
$tier1 = $users->filter(fn ($u) => $this->resolveTierId($u) === 1);  // PHP-side
$page  = $tier1->slice($offset, $limit);

// Correct
User::query()
    ->where('tier_id', $tierId)                                  // SQL
    ->orderBy('id')
    ->offset($offset)->limit($limit)
    ->get();
```

If the filter depends on logic that cannot be expressed in SQL (e.g., parsing a JSON
column with a complex schema), persist a denormalized column at write time and filter
on that — never make every read pay the parsing cost.

### 38.6 Helper logic duplicated between Schema getter and controller

When a `Schema\*->get(fn ... => $this->resolveX($user))` and a controller both contain
the same `resolveX` logic, the next bug is **drift** — one place gets a fix, the other
doesn't. The fix is structural: put the logic on the **model** as an accessor
(`getXAttribute` / `Attribute::make`) or a method, so both call sites read the same
implementation. Reference smell: `resolveTierId` duplicated between
`UserResourceFields` and `ListApprovedUsersController` in a verification-style extension.

---

## §39. Flarum version compatibility & portability

### 39.1 `composer.json` constraint must match the API surface the code uses

Flarum 2.x introduced a new API resource layer (`Flarum\Api\Resource\AbstractDatabaseResource`,
`Flarum\Api\Schema\*`, `Flarum\Api\Endpoint\*`) that **does not exist on 1.x**. An
extension that imports those classes but ships `"flarum/core": "^1.0 || ^2.0"` in
`composer.json` will install cleanly on a 1.x forum and then fatal-error on enable.

**Locate**:

```bash
# Does the code use v2-only classes?
rg -n "use Flarum\\\\Api\\\\(Resource|Schema|Endpoint|Context|Sort|Include_)" src/

# What does the manifest claim?
rg -n "\"flarum/core\"" composer.json
```

**Rules**:
- If `src/` uses any class under `Flarum\Api\Resource`, `Flarum\Api\Schema`, `Flarum\Api\Endpoint`, `Flarum\Api\Context` → constraint MUST be `"flarum/core": "^2.0"` (no `^1.0`).
- If you want **dual-version support**, you need two code paths, two extender sets in `extend.php`, and runtime detection via `\Composer\InstalledVersions::satisfies(...)`. This is rarely worth the complexity — almost every extension should commit to one major version.
- The `flarum-extension.json` (legacy) and `extra.flarum-extension` block in `composer.json` must agree with the constraint.
- Don't claim v1 compatibility "just in case" — reviewers and `flarum/extension-manager` enforce the constraint, and the white-screen fatal on activation is a much worse failure mode than a clear "requires Flarum 2.x" install error.

**Migration class deltas** (the v1 → v2 surfaces that LLMs reach for by reflex):

| v1 only | v2 only | Both (no rename) |
|---|---|---|
| `Flarum\Api\Serializer\AbstractSerializer` | `Flarum\Api\Resource\AbstractDatabaseResource` | `Flarum\User\User` |
| `Flarum\Api\Controller\AbstractCreate/Show/List/Update/Delete*` | `Flarum\Api\Endpoint\Create/Show/Index/Update/Delete::make()` | `Flarum\Foundation\AbstractValidator` |
| `Flarum\Extend\ApiSerializer/ApiController` | `Flarum\Api\Schema\Str/Boolean/Integer/Arr/Relationship` | `Flarum\Extend\Routes/Middleware/Policy/Settings/Locales` |
| (n/a) | `Flarum\Api\Context` (handler arg) | `Flarum\User\Access\AbstractPolicy` |

### 39.2 Database portability — no MySQL-only SQL in migrations

Flarum officially supports **MySQL/MariaDB and PostgreSQL**, with SQLite for tests.
Direct `INFORMATION_SCHEMA` queries, `RAND()` (`RANDOM()` on PG/SQLite), `FROM_UNIXTIME`,
`GROUP_CONCAT`, MyISAM-specific DDL, and the JSON syntax variants are all portability
hazards.

**Locate**:

```bash
rg -n "INFORMATION_SCHEMA|FROM_UNIXTIME|GROUP_CONCAT|RAND\\(\\)" migrations/ src/
rg -n "ENGINE=|->engine\\(" migrations/
```

**Correct shape**:

```php
// Anti-pattern — works on MySQL, fails on PostgreSQL
$db->select("SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS WHERE TABLE_NAME = 'x' AND INDEX_NAME = 'y'");

// Portable — Laravel Schema Builder works on both
use Illuminate\Database\Schema\Builder;
return [
    'up' => function (Builder $schema) {
        if (! $schema->hasTable('verification_requests')) return;
        if ($schema->getConnection()->getDoctrineSchemaManager()
                ->listTableIndexes('verification_requests')['idx_user_status'] ?? null) return;
        $schema->table('verification_requests', function ($table) {
            $table->index(['user_id', 'status'], 'idx_user_status');
        });
    },
];
```

If you genuinely need a database-vendor-specific feature, gate it on the connection
driver: `if ($schema->getConnection()->getDriverName() === 'mysql') { … }`.

### 39.3 Eloquent first, `ConnectionInterface` second

Reiterating §10: prefer an Eloquent model. The convention smell flagged in reviews is
not "you used the DB" — it's "you injected a low-level abstraction when a higher-level
one was already wired by Flarum". Reach for `ConnectionInterface` only for truly raw
work (bulk insert, cross-connection queries, vendor-specific SQL gated as in §39.2).
Most "needs raw SQL" cases dissolve into `Model::query()->whereHas(...)->withCount(...)`.

---

## §40. Frontend robustness, TS discipline, CSS targeting

This section collects the JS/TS/CSS patterns that reviewers consistently flag as
low/medium severity. Individually each is trivial; collectively they're what drives
quality scores from 94 down to 67.

### 40.1 `JSON.parse` on XHR responses must be wrapped

```ts
// BAD — bare parse, ANY non-JSON response (HTML error page, gateway timeout)
// becomes an uncaught exception that the user never sees.
xhr.onload = () => {
    const data = JSON.parse(xhr.responseText);                   // ← throws SyntaxError
    onSuccess(data);
};

// GOOD
xhr.onload = () => {
    let data: unknown;
    try { data = JSON.parse(xhr.responseText); }
    catch (e) {
        app.alerts.show({ type: 'error' },
            app.translator.trans('myext.import.parse_error'));
        return;
    }
    onSuccess(data);
};
```

The same rule applies to `await response.json()` in `fetch` — wrap it. The browser will
NOT show the user a meaningful error otherwise; they just see a button that did
nothing.

### 40.2 User-visible error UI on every async failure

Every `.catch(...)`, every `try/catch` around an `await`, every XHR `onerror` must
surface something — `app.alerts.show({type:'error'}, …)`, a toast, an inline error
state on the form. Returning silently from a failure is worse than throwing: the user
clicks "Save", nothing happens, they click again, eventually the form is in an
unknowable state. Reviewers flag this as `robustness` and it accumulates.

```ts
// BAD
async function save() {
    try { await app.request({…}); this.dismiss(); }
    catch { /* swallowed */ }
}

// GOOD
async function save() {
    this.loading = true;
    try {
        await app.request({…});
        this.dismiss();
    } catch (e) {
        this.loading = false;
        const msg = e?.response?.errors?.[0]?.detail
            ?? app.translator.trans('myext.save_failed');
        app.alerts.show({ type: 'error' }, msg);
        m.redraw();
    }
}
```

### 40.3 DOM queries — scope to `this.element`, never `document`

```ts
// BAD — picks the FIRST .Button-Sticker anywhere in the document, often the wrong one
const button = document.querySelector('.Button-Sticker');

// GOOD — scope to the component's own DOM
const button = this.element.querySelector('.Button-Sticker');

// BETTER — use Mithril refs / element bindings; touching the DOM at all is a smell
```

In a Flarum SPA, multiple component instances coexist on the same page. A reply form
above the composer and one inside the composer both render `.Button-Sticker`. A
`document.querySelector` will reach for whichever the DOM happens to list first, which
is a hidden coupling to render order. Reviewers flagged exactly this pattern in a
sticker-style extension.

### 40.4 `as any` — prefer module augmentation

`as any` casts bypass TypeScript silently. They surface as "low" severity in review
but accumulate into "we can't safely refactor this file" debt.

```ts
// BAD
(MyClass.prototype as any).newMethod = function () {…};

// GOOD — augment the type
declare module 'flarum/forum/components/MyClass' {
    export default interface MyClass {
        newMethod(): void;
    }
}
MyClass.prototype.newMethod = function () {…};
```

For tag-type extensions adding attributes to core models, augment the model class:

```ts
declare module 'flarum/common/models/User' {
    export default interface User {
        isVerified(): boolean;
        verifiedBadgeUrl(): string | null;
    }
}
```

### 40.5 Modern CSS — check Flarum's browserslist before shipping

Flarum 1.x has a wider browser target than 2.x. Features like `color-mix()`,
`:has()`, container queries, and the `oklch()` color space are not universally
supported across the target list. **If the feature degrades gracefully** (fallback to
a static color), ship it. If it doesn't degrade (the rule disappears entirely), provide
a fallback first:

```less
.Button {
    // Fallback — works everywhere
    background: darken(@primary-color, 10%);

    // Progressive enhancement — used when supported
    @supports (background: color-mix(in srgb, red, blue)) {
        background: color-mix(in srgb, @primary-color 90%, black);
    }
}
```

Reviewers will downgrade for a missing fallback that breaks hover/active states on
Safari/older Chromium even though the feature is "broadly available" per caniuse.

### 40.6 Hardcoded list truncation must surface to the user

```ts
// BAD — silently drops anything past 500
const visible = stickers.slice(0, 500);

// GOOD — page through, or show the count
const PAGE = 500;
const visible = stickers.slice(0, PAGE);
if (stickers.length > PAGE) {
    items.add('overflow-note',
        <p className="muted">{app.translator.trans('myext.showing_n_of_m',
            { n: PAGE, m: stickers.length })}</p>);
}
```

If 500 is enough for any realistic install, document it; if not, paginate or virtualize.
**Silent truncation** is the worst option: users on a 600-sticker library think their
last 100 stickers were deleted.

### 40.7 Helper deduplication across components

```bash
# Find the same function defined in multiple files
rg -n "function isLottiePath|const isLottiePath|function isTgsPath|const isTgsPath" js/src/
```

When the same helper appears in 3 files, extract it to `js/src/common/utils/<name>.ts`
and `export`. Reviewers flag this as `technical debt`; the real cost surfaces when one
copy fixes a bug and the other two don't.

### 40.8 Unreachable CSS — feature blocks for code paths that don't ship

```bash
# CSS rules referencing class names that no JS/PHP emits
rg -n "\\.MyExt-coloredHeader|\\.MyExt-experimental" less/ src/
```

A `.less` block targeting `.MyExt-coloredHeader` only matters if some component renders
that class. If grep against `js/src/` and templates returns zero hits, the CSS is dead
weight — and worse, the next reader assumes the feature exists and looks for the JS
that wires it. Delete the block; if the feature is planned, put it on a branch.

---

## §41. Logging discipline — PSR-3 `LoggerInterface`, never `Facades\Log`

Flarum binds `Psr\Log\LoggerInterface` to a rotating-file logger out of the box. Inject
it — don't reach for `Illuminate\Support\Facades\Log`. The Facade only works because
Flarum boots a Laravel container; it adds a hidden global dependency, breaks under
tests that don't boot the facade root, and obscures the dependency graph.

**Locate**:

```bash
rg -n "use Illuminate\\\\Support\\\\Facades\\\\Log|\\\\Log::" src/
rg -n "use Psr\\\\Log\\\\LoggerInterface" src/
```

**Anti-pattern (pervasive, recently flagged)**:

```php
use Illuminate\Support\Facades\Log;
class MyHandler {
    public function handle(...): ResponseInterface {
        Log::info('user did thing', ['actor' => $actor->id]);    // ← global facade
    }
}
```

**Correct shape**:

```php
use Psr\Log\LoggerInterface;
class MyHandler {
    public function __construct(private LoggerInterface $log) {}
    public function handle(...): ResponseInterface {
        $this->log->info('user did thing', ['actor' => $actor->id]);
    }
}
```

When the class is a singleton/handler resolved by the container, Flarum injects the
logger automatically. For values that flow through queued jobs, the job's `handle()`
gets the same container resolution — same shape.

Re-read §23 for **what** to log (don't log request bodies, headers, tokens). This
section is about **how** to obtain the logger.

---

## §42. Project hygiene & scaffolding completeness

The single most common rejection reason in code review is "this extension does almost
nothing" — empty scaffolding, `console.log` debug calls in the shipped bundle, stale
boilerplate metadata from a template, and `.less`/`locale` files referenced by
`extend.php` that don't exist on disk. None of these are vulnerabilities. Together
they tank the quality score and signal "vibe-coded, not reviewed" to reviewers,
which is enough to fail listing.

### 42.1 The empty-skeleton smell

Symptoms reviewers flag:
- `extend.php` returns `[]` or only locale/frontend extenders — no routes, no models, no resources.
- `js/src/forum/index.{js,ts}` body is `app.initializers.add('myext', () => { console.log('myext booted'); });`.
- `src/` directory exists but contains only the namespace declaration in one file with no class body, or a `Stub.php` from the `flarum/cli` template.
- `README.md` advertises features the code doesn't implement.

**Rule**: if a forum operator installs the extension today, what concrete thing
changes for them? If the answer is "nothing visible", the extension is not ready to
list. Either implement the advertised features OR mark the package
`"abandoned": true` in `composer.json` until it is.

```bash
# Find debug-only entry points
rg -n "console\\.log\\(|console\\.debug\\(|console\\.warn\\(" js/src/ js/dist/
rg -n "console\\.log\\(" js/dist/ --type js          # the BUILT bundle, not just src

# Find empty PHP files (one short class with no body)
find src -name '*.php' -size -2k -print0 | xargs -0 -I {} sh -c 'echo "== {} =="; wc -l "{}"'
```

`console.log` in `js/dist/` ships to every visitor's browser console. It's harmless
but reviewers grade it as "production hygiene: 0/3". Strip with webpack
`TerserPlugin` `drop_console: true` in production mode, or guard with
`if (process.env.NODE_ENV !== 'production') console.log(...)`.

### 42.2 Stale boilerplate from `flarum/cli`

`flarum/cli` generates a `composer.json` with placeholder values in `extra.flarum-extension`,
sometimes carrying vendor names from older forks (`flagrow.discuss`, `reflar.foo`,
`fof.bar`). Reviewers grep for these and flag any extension still carrying them.

```bash
# Stale vendors and template placeholders
rg -n "flagrow|reflar|fof\\.|YOUR_VENDOR|YOUR_EXTENSION|TODO|FIXME|XXX" composer.json
rg -n "Acme|Vendor|MyVendor|ChangeMe" composer.json src/ js/src/
```

The `extra.flarum-extension` block must list **only** your extension's title, icon
config, and category, with values that actually describe the extension. Empty or
template values are read by `flarum/extension-manager` and surface in the admin UI as
"Untitled" or as the wrong icon.

### 42.3 Referenced assets that don't exist

`extend.php` lines like `new Extend\Locales(__DIR__.'/locale')` or
`(new Extend\Frontend('forum'))->js(__DIR__.'/js/dist/forum.js')->css(...)` are read
at boot. Missing files don't error loudly — they just don't ship the asset, and the
feature silently doesn't render.

```bash
# Verify every path referenced from extend.php actually exists
rg -n "__DIR__\\.\\s*'/[^']+'" extend.php
# For each path, test:
test -e "<extracted-path>" || echo "MISSING: <extracted-path>"

# Locale files must contain non-empty YAML
for f in locale/*.yml; do
    [ -s "$f" ] || echo "EMPTY LOCALE: $f"
done
```

Empty `locale/en.yml` is the silent killer: every translator key falls back to its
literal slug, the admin UI shows `myext.settings.label` instead of "My setting", and
the extension looks broken without any error message.

### 42.4 PHPStan / type-check disabled in CI

A `.github/workflows/ci.yml` block that runs PHPStan but exits 0 on failure (or
prints "skipping PHPStan" because the dev dependency is missing) gives a false green
check. Reviewers grade this as a `technical debt` finding because every type bug
silently ships.

```bash
rg -n "phpstan|psalm" composer.json .github/
rg -n "continue-on-error:\\s*true|exit 0" .github/workflows/
```

Either:
- Wire PHPStan **as a blocking step** (`composer require --dev phpstan/phpstan:^1 flarum/phpstan-stub`, then `vendor/bin/phpstan analyse --level=max src/ extend.php`), OR
- Don't ship a PHPStan step at all. A "disabled with a printed warning" step is worse than no step.

The same applies to TypeScript's `tsc --noEmit`, ESLint, Prettier, and `composer
audit` — make them blocking or remove them.

### 42.5 Built artifacts in `js/dist/`

`js/dist/{forum,admin}.js` is checked into git so that `composer require` works
without a Node toolchain on the production host. The artifact MUST:
- Be regenerated and committed in the SAME commit as the JS source change. A
  `composer.json` version bump that ships outdated `dist/` is a regression — users get
  yesterday's UI with today's backend.
- Be a production build (`webpack --mode production`), not a development build with
  source maps and debug shims.
- NOT contain `console.log`, `debugger;`, or sourcemap-inline base64 in the bundle.

### 42.6 Common quality-score deductions reviewers apply

| Symptom | Severity | Section to read |
|---|---|---|
| Empty `extend.php` or `src/` for an extension claiming features | High (production risk) | §42.1 |
| `console.log` in `js/dist/` | Medium (dead code) | §42.1 |
| Stale `flagrow.*` / `reflar.*` / placeholder `extra.flarum-extension` | Medium (technical debt) | §42.2 |
| Referenced locale/asset directory missing | Medium (dead code) | §42.3 |
| PHPStan disabled with `continue-on-error: true` | Medium (technical debt) | §42.4 |
| Outdated `js/dist/` not regenerated for the JS change | High (production risk) | §42.5 |
| Imports of components never rendered | Low (dead code) | §31 |
| Translator key typo silently breaks notification type | Medium (dead code) | §46.2 |

---

## §43. Composer constraints & dependency contracts

The `composer.json` of an extension is a public contract: what version of Flarum core
the code runs on, which optional integrations exist, and how the package interacts
with the host forum's lockfile. Reviewers flag mismatches as `conventions` findings,
but the underlying impact is real — too-loose constraints break installs in
production, too-tight ones lock operators into manual updates.

### 43.1 `flarum/core` constraint must match the API surface in `src/`

§39.1 covered the rough rule; this section is the operational checklist.

```bash
# What API surface does the code use?
rg -n "use Flarum\\\\(Api\\\\(Resource|Schema|Endpoint|Context)|Forum\\\\Controller\\\\FrontendController)" src/ extend.php

# What does composer.json claim?
rg -n "\"flarum/core\"" composer.json
```

Decision matrix:

| Imports include `Flarum\Api\(Resource|Schema|Endpoint|Context)` | Constraint | Why |
|---|---|---|
| Yes (any of them) | `"flarum/core": "^2.0"` | v1 doesn't have these namespaces; install crashes on enable |
| No, only legacy `AbstractSerializer`/`AbstractController` | `"flarum/core": "^1.0"` | v2 supports v1-style for now, but consider migration |
| Neither (only `Extend\Routes`/`Extend\Settings`/translator/Eloquent) | `"flarum/core": "^1.0 \|\| ^2.0"` is **acceptable but rare** | Almost every real extension touches a Resource or Endpoint |

**Anti-pattern**: shipping `"flarum/core": "^1.0 || ^2.0"` for an extension whose
`src/` is full of v2-only classes. The composer install succeeds on a v1 forum; the
extension activation triggers a fatal "Class not found". The operator sees a
white-screened admin panel.

### 43.2 `flarum-extension.json` (legacy) and `extra.flarum-extension` must agree

`composer.json` carries the canonical `extra.flarum-extension` block:

```json
{
  "extra": {
    "flarum-extension": {
      "title": "My Extension",
      "category": "feature",
      "icon": { "name": "fas fa-star", "backgroundColor": "#222", "color": "#fff" }
    }
  }
}
```

The title appears in the admin UI; the icon renders in the extension card; the
category groups extensions. Boilerplate carryover from `flarum/cli` (title:
"Acme Extension", category: `feature` when actually a `theme`) is what's flagged as
"stale metadata". Walk the file and replace every placeholder.

### 43.3 Sister-extension version pinning

When your extension integrates with another extension (suggests, requires, or events
it listens for), constrain the version explicitly. `"flarum/tags": "*"` accepts any
release including a future v3 with breaking API changes; the next forum operator
upgrade silently breaks your integration.

```json
{
  "require": {
    "php": "^8.2",
    "flarum/core": "^2.0",
    "flarum/tags": "^2.0"             // version-bounded, not "*"
  },
  "suggest": {
    "flarum/gdpr": "Required for data export/erasure integration (^2.0).",
    "flarum/likes": "Adds bounty rewards on liked posts (^2.0)."
  }
}
```

`*` on a `require` constraint is **🟡 low** — it works today but creates a future
support burden. Reviewers flag it.

### 43.4 `require` vs `suggest` — the integration gate

If your extension's core feature works without extension X, list X under `suggest`
and wrap its wiring in `class_exists`/container `bound()` checks. If X is mandatory,
list it under `require` and let composer enforce it.

Operational rule: **`require` should only contain things the extension cannot boot
without.** A "nice to have" integration that improves UX when present but doesn't
break when absent goes in `suggest`.

```php
// extend.php — class_exists gate for suggested integrations
$extenders = [
    // ... mandatory wiring ...
];

if (class_exists(\Flarum\Gdpr\Extend\UserData::class)) {
    $extenders[] = (new \Flarum\Gdpr\Extend\UserData())->addType(MyData::class);
}

if (class_exists(\Flarum\Tags\Tag::class)) {
    $extenders[] = (new Extend\Model(\Flarum\Tags\Tag::class))->hasMany(...);
}
```

A review finding "GDPR Erasing event dependency not declared in composer.json"
typically means: the extension listens to `Flarum\Gdpr\Events\Erased` in `extend.php`
**without a class_exists guard AND without a composer require**. Pick one — guard
the listener if GDPR is optional, or require GDPR if it's mandatory.

### 43.5 PHP version constraint

`"php": "^8.2"` is the current Flarum 2.x baseline. Test against the matrix in §35.2
(8.2/8.3/8.4). Don't claim `"^8.0"` — Flarum 2 relies on 8.1+ features (readonly,
first-class callable syntax, enums), and your code will fail-fast on 8.0 hosts.

### 43.6 Quick grep audit

```bash
# Constraint vs API surface
rg -n "\"flarum/core\":\\s*\"[^\"]+\"" composer.json
rg -n "use Flarum\\\\Api\\\\(Resource|Schema|Endpoint)" src/

# Unbounded sister-extension requires
rg -n "\"flarum/[^\"]+\":\\s*\"\\*\"" composer.json

# Listeners or extenders for a class that isn't required or guarded
rg -n "\\\\Gdpr\\\\Events\\\\|\\\\Tags\\\\Tag::|\\\\Subscriptions\\\\" extend.php src/
# Cross-reference each hit with composer.json require/suggest and class_exists guards
```

---

## §44. Long-lived process state & PHP global handlers

The classic mod_php / php-fpm execution model is **single-shot**: every request gets a
fresh PHP process, every global resets, every static is empty. Flarum extensions are
written against this assumption. The model breaks in:

- **Queue workers** — `php flarum queue:work` keeps one PHP process alive across
  thousands of jobs.
- **Scheduled-command processes** — long-running `php flarum schedule:work`.
- **FrankenPHP / RoadRunner / Swoole / Octane** — increasingly common production
  hosting, one process per worker, sometimes for hours.

In these contexts, **static properties, container singletons, and global PHP error
handlers persist across requests/jobs**. Code that relies on "fresh process" semantics
either leaks data between actors or breaks subsequent requests entirely.

### 44.1 `set_error_handler` MUST chain previously-registered handlers

`set_error_handler` returns the **previous** handler. Sentry, Bugsnag, Flarum's own
`ErrorHandler` middleware, the Whoops integration — all of them call
`set_error_handler` during boot. If your extension overrides it without preserving
the chain, every downstream handler stops receiving errors.

```php
// BAD — replaces every previously-registered handler
set_error_handler(function ($severity, $message, $file, $line) {
    MyReporter::report($message);
});

// GOOD — chain explicitly
$previous = set_error_handler(function ($severity, $message, $file, $line) use (&$previous) {
    MyReporter::report($message);
    if (is_callable($previous)) {
        return $previous($severity, $message, $file, $line);
    }
    return false;                                       // false = continue to PHP default
});
```

`set_exception_handler` and `register_shutdown_function` have the same chaining
contract:
- `set_exception_handler` returns the previous, call it from yours.
- `register_shutdown_function` does NOT replace; multiple shutdowns are queued and
  called in registration order. Don't try to "unregister" by overwriting.

### 44.2 Static properties on Eloquent models

A static cache on an Eloquent class that's `protected static array $cache = []` is
shared across every request handled by the same worker. In php-fpm: never matters. In
queue worker: cache from job N is visible to job N+1, including any actor-specific
state. The example reviewers flag most often is "user-context attached to a query
scope via static":

```php
// BAD — leaks across actors in long-lived processes
class MyModel extends AbstractModel {
    protected static ?User $contextActor = null;
    public static function forActor(User $actor): self {
        self::$contextActor = $actor;
        return new self();
    }
}

// GOOD — pass actor through the call chain, never static
class MyModel extends AbstractModel {
    public function scopeForActor(Builder $query, User $actor): Builder {
        return $query->where('owner_id', $actor->id);
    }
}
```

The same rule applies to query-result caches, permission caches, and "compiled
config" caches: bind them to a per-actor key (§24) or flush them between jobs via
the queue's `JobProcessed` event.

```bash
rg -n "protected static (\\\$|array|?\\??)" src/         # static properties
rg -n "private static (\\\$|array|?\\??)" src/
rg -n "self::\\\$|static::\\\$" src/                      # static reads/writes
```

`flarum/tags` uses a `WeakMap`-keyed cache **bound to the User instance** plus an
explicit `flush()` for queue workers — see §34/P. Mirror that pattern, not raw
`static`.

### 44.3 Container `resolve()` / `app('foo')` without `bound()` check

`resolve('gdpr.user.reservedAbilities')` and `app('sentry.request')` are
container-resolution shortcuts. If the binding doesn't exist (e.g., the suggested
extension isn't installed), they throw a `BindingResolutionException`. In a
constructor that runs on every boot, the throw kills the entire forum.

```php
// BAD — assumes the binding exists
class MyPolicy extends AbstractPolicy {
    public function __construct() {
        $this->reservedAbilities = resolve('gdpr.user.reservedAbilities');
    }
}

// GOOD — check before resolving
class MyPolicy extends AbstractPolicy {
    public function __construct(Container $container) {
        $this->reservedAbilities = $container->bound('gdpr.user.reservedAbilities')
            ? $container->make('gdpr.user.reservedAbilities')
            : [];
    }
}
```

The pattern in `vendor/flarum/gdpr/src/Access/UserPolicy.php:21` works because the
GDPR provider always registers the binding before policies resolve — but it relies on
gdpr being installed. An extension consuming gdpr's bindings from outside that
package must guard with `bound()`.

```bash
rg -n "resolve\\(\\s*['\"]" src/
rg -n "app\\(\\s*['\"][^'\"]+['\"]\\s*\\)" src/
```

For each hit: is the resolved key bound by core, or by an extension your `extend.php`
required? If the latter, wrap in `bound()` or require the extension explicitly.

### 44.4 Singletons and `Extend\ServiceProvider`

Service providers registering singletons (`$this->container->singleton(...)`) tie the
singleton's lifetime to the container — which lives for the entire long-lived
process. Don't store request-scoped data in a singleton. If you need per-request
state, scope to `bindIf` + manual flush, or pass state through the call chain.

### 44.5 Queue worker cleanup hooks

For state that genuinely must persist within a request but never bleed across jobs,
hook the `Illuminate\Queue\Events\JobProcessed` event and flush:

```php
(new Extend\Event())
    ->listen(\Illuminate\Queue\Events\JobProcessed::class, function () {
        \Vendor\MyExt\State::flushPerRequest();
    });
```

This is also where you'd flush an internal request-scoped cache between job runs in
a worker that handles dozens of jobs per minute.

---

## §45. Migrations on core tables

The single highest-severity production-risk finding in recent reviews has been
**migrations that `ALTER TABLE` against core's `users`, `discussions`, `posts`, or
`discussion_user` tables**. The damage isn't a bug — it's downtime: an online
`ALTER TABLE` on a `users` table with 5 million rows can lock the table for minutes
on MySQL <8.0 / MariaDB, taking the forum offline during the install. On a community
running on managed MySQL with no `pt-online-schema-change`, the operator has no
escape hatch.

### 45.1 The companion table convention

**Rule**: extension data NEVER goes on a core table. Always a companion table with a
1:1 or 1:many FK back to the core row, cascading on delete.

```bash
# Find offenders
rg -n "Schema::table\\('(users|discussions|posts|discussion_user|groups|tags)'" migrations/
rg -n "->table\\('(users|discussions|posts|discussion_user|groups|tags)'\\)" migrations/
```

**Anti-pattern** (a finding flagged recently as 🟠 high):

```php
// migrations/2026_03_01_000000_add_verification_columns_to_users.php
return Migration::addColumns('users', [
    'verification_status' => ['string', 50, 'nullable' => true],
    'verified_at'         => ['dateTime', 'nullable' => true],
    'verification_note'   => ['text', 'nullable' => true],
]);
```

**Correct shape**:

```php
// migrations/2026_03_01_000000_create_user_verifications_table.php
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Schema\Builder;

return [
    'up' => function (Builder $schema) {
        if ($schema->hasTable('user_verifications')) return;

        $schema->create('user_verifications', function (Blueprint $table) {
            $table->unsignedInteger('user_id')->primary();    // 1:1 — PK is user_id
            $table->string('status', 50);
            $table->dateTime('verified_at')->nullable();
            $table->text('note')->nullable();
            $table->timestamps();

            $table->foreign('user_id')
                  ->references('id')->on('users')
                  ->cascadeOnDelete();                        // user delete cascades
        });
    },
    'down' => function (Builder $schema) {
        $schema->dropIfExists('user_verifications');
    },
];
```

Then on the User model in `extend.php`:

```php
(new Extend\Model(User::class))
    ->hasOne('verification', UserVerification::class, 'user_id'),
```

…and in `src/Models/UserVerification.php`:

```php
class UserVerification extends AbstractModel
{
    protected $table = 'user_verifications';
    protected $primaryKey = 'user_id';
    public $incrementing = false;
}
```

### 45.2 Why the companion table convention is non-negotiable

1. **Multi-extension safety**: two extensions adding columns to `users` step on each
   other's migrations, and if both add `verified` with different semantics, install
   order decides which wins.
2. **Uninstall is reversible**: dropping a companion table is one statement;
   undoing column additions to `users` requires the operator to trust the down
   migration.
3. **Online DDL on core tables takes locks**: even MySQL 8 `ALGORITHM=INPLACE`
   migrations briefly lock the table, and on tables the SPA polls every few seconds
   (the `users` row of the actor on every authenticated request), that's a visible
   spike.
4. **Audit / GDPR cleanliness**: a companion table is opt-in to `Data\User` export
   (you write your own `DataType`). Columns on `users` are pulled in automatically
   by `Flarum\Gdpr\Data\User` and may need to be added to `removeUserColumns()` —
   easy to forget.
5. **Migration ordering**: when your extension is uninstalled and reinstalled (e.g.,
   to upgrade), columns added directly to `users` either persist (orphan) or get
   re-added with `if (! Schema::hasColumn(...))` guards that drift between
   extensions.

### 45.3 The "retroactive violation" remediation path

If you inherited an extension that added columns to `users`, you cannot just delete
the migration — production forums have the columns. The remediation is:

1. New migration creates the companion table.
2. New migration copies data: `INSERT INTO user_verifications (user_id, status, ...) SELECT id, verification_status, ... FROM users WHERE verification_status IS NOT NULL`.
3. New migration drops the columns from `users`.
4. Update all readers to use the companion model.
5. Bump major version — this is a breaking schema change for downstream extensions reading the old columns.

This is expensive enough that reviewers flag the original violation as 🟠 high — the
remediation cost is paid forever.

### 45.4 Reading core-table columns from a relation, not the row

```php
// BAD — re-introduces dependency on a column being on `users`
$status = $user->verification_status;

// GOOD — companion relation
$status = $user->verification?->status;
```

For Schema fields exposing the relation's data, use `->property(...)` on a Schema field
backed by an Eloquent accessor that reads through the relation, plus `eagerLoad` on
the resource's `Index` endpoint (§38.1).

### 45.5 Quick checklist

- [ ] No `Schema::table('users'/'discussions'/'posts'/...)` in migrations.
- [ ] Every extension table has an explicit FK back to the core table it relates to.
- [ ] FK has `cascadeOnDelete()` (or `nullOnDelete()` if the row should survive deletion).
- [ ] Composite or covering index for the most common `WHERE` shape (see §38.3).
- [ ] `extend.php` wires the relation via `Extend\Model->hasOne()`/`->hasMany()`.
- [ ] No reader code casts `$user->custom_column` — every read goes through the relation.

---

## §46. Event listener / blueprint subject-type contracts

Flarum's polymorphic associations (`subject_type` + `subject_id` on
`notifications` and `subscriptions`, `commentable_type` on the activity log if
enabled) trust the writer. Whatever class string you stuff into `subject_type` is
what the loader will `instanceof` against — there is no compile-time check that the
type you wrote is the type the consumer expects. Passing the wrong model corrupts
the polymorphic pair: the loader fetches a row of the wrong table by an ID that
happens to collide.

### 46.1 The Blueprint subject contract

A `Blueprint` declares a "subject" by returning a model from `getSubject()`. The
notification table stores `subject_type = get_class($blueprint->getSubject())` and
`subject_id = $blueprint->getSubject()?->id`. When the frontend renders the
notification, it issues `GET /api/notifications` which includes the subject via a
sparse fieldset matching `subject_type`. If `subject_type` is `User` but the
notification is "about a Discussion the user posted in", every consumer using the
subject is reading user N with the discussion's ID.

**Anti-pattern** flagged in a recent review (paraphrased):

```php
// UponUserDeletion handler — wrong subject
class UponUserDeletion {
    public function handle(UserDeleted $event): void {
        foreach ($event->user->subscriptions as $sub) {
            // BAD — $event->user is the User, but $sub expects a Discussion/Tag
            event(new SubscriptionCancelled($event->user, $sub));
        }
    }
}
```

`SubscriptionCancelled` was modelled to carry the `Subscription` and **the
subscription's subject model** (the Discussion or Tag the subscription was for).
Passing the User as the second argument silently writes `User` into the subject
column for every downstream listener — discussion-level subscription listeners then
fail on `instanceof Discussion`, group-level listeners fail on `instanceof Group`, and
the actual cancellation work doesn't happen.

**Correct shape**:

```php
foreach ($event->user->subscriptions as $sub) {
    event(new SubscriptionCancelled($event->user, $sub->subject));  // resolved through subject morph
}
```

For your own blueprints, declare and enforce the subject type at the construction
site:

```php
class MyBlueprint implements BlueprintInterface
{
    public function __construct(public Discussion $discussion) {}   // typed constructor

    public function getSubject(): ?AbstractModel { return $this->discussion; }
    public function getType(): string             { return 'myextDiscussionFoo'; }
    public function getData(): mixed              { return ['discussionId' => (int) $this->discussion->id]; }
}
```

The typed constructor (`public Discussion $discussion`) is the contract. A caller
can't accidentally pass `User` — PHP throws a `TypeError` at construction.

### 46.2 Notification type strings — server and frontend must agree byte-for-byte

`Blueprint::getType()` returns a string like `myextDiscussionFoo`. The frontend reads
the same string via `app.store.find('notifications')` and dispatches to a renderer
registered as `app.notificationComponents['myextDiscussionFoo'] = MyComponent`. A
typo in either string (`myextDiscussionFoo` vs `myextDiscussionFooo`) silently breaks
the renderer: the notification arrives, but the frontend has no component for the
type and renders blank.

A reviewer recently flagged "Frontend notification type key typo —
`byobuPrivateDiscussionMadePubic` (missing `l`) means the made-public alert never
fires". The bug is invisible without a manual smoke test because the notification
still appears in the DB, the API still serves it, and no error surfaces in the
console.

**Rule**: declare the type string ONCE, as a class constant on the blueprint, and
import it into JS via a translator key or a serializeToForum attribute.

```php
// PHP
class MyBlueprint implements BlueprintInterface
{
    public const TYPE = 'myextDiscussionFoo';

    public function getType(): string { return self::TYPE; }
}
```

```ts
// JS — read it from the server-provided forum attribute, never literal
app.notificationComponents[app.forum.attribute('myextNotificationType')] = MyComponent;
```

This is over-engineered for a single notification type but is the only structural
fix that survives renames. For 2–3 types, just have a code-review checklist:
"compare `getType()` against the JS string verbatim".

### 46.3 `beforeSending` recipient filter — re-checking visibility

Even with the correct subject, a notification's recipient list must be re-filtered
through `can('view', $subject)` (§19). The `Extend\Notification::beforeSending`
filter is the canonical hook:

```php
// extend.php
(new Extend\Notification())
    ->beforeSending(MyBlueprint::class, MyBlueprintRecipientFilter::class);
```

```php
class MyBlueprintRecipientFilter
{
    public function __invoke(MyBlueprint $blueprint, array $users): array
    {
        return array_values(array_filter(
            $users,
            fn (User $u) => $u->can('view', $blueprint->discussion)
        ));
    }
}
```

`flarum/subscriptions` does this for `FilterVisiblePostsBeforeSending`
([vendor/flarum/subscriptions/src/Notification/FilterVisiblePostsBeforeSending.php:24](../../vendor/flarum/subscriptions/src/Notification/FilterVisiblePostsBeforeSending.php#L24)).
Copy the shape.

### 46.4 `getData()` payload — IDs only, never content

Re-stating §19: the `data` JSON column is returned verbatim with no policy re-check
at read time. Put **IDs and primitive scalars only**. The frontend rehydrates via the
subject relation, which IS visibility-gated.

```bash
rg -n "function getData\\(" src/
```

For each blueprint's `getData()`, verify the return is only `int`/`string`/`bool` IDs.
Any user-controlled string, free-text content, or other-user identifier is a leak
vector.

### 46.5 Subject-type contracts when extending another extension's blueprint

If you `Extend\Notification::type(OtherExtensionBlueprint::class, ['alert', 'email'])`
to plug an existing blueprint into a new channel, you inherit that blueprint's
subject type contract. You can't change the subject — you can only adapt the
rendering. Don't override `getSubject` via reflection or trait magic; that's the path
to "discussion-typed subjects served as users".

---

## §47. Admin-controlled execution surfaces

An admin compromise is not the same threat model as a guest compromise, but
defense-in-depth principles still apply. An extension that says "admins paste raw JS
here and it runs in every visitor's browser" creates a **persistent stored-XSS
primitive** that survives an admin password rotation: an attacker who briefly
compromises admin credentials (phishing, session hijack, leaked panel password)
plants the payload, and every subsequent visitor executes it until the next admin
notices. The trade-off is sometimes acceptable — Flarum core itself exposes
`headerHtml` / `footerHtml` / `customCss` / `welcomeMessage` for this reason — but
new extensions should not casually add to the surface.

### 47.1 The `createContextualFragment` trap

```ts
// BAD — executes script tags
const range = document.createRange();
range.selectNode(document.body);
const fragment = range.createContextualFragment(adminProvidedHtml);
document.body.appendChild(fragment);
```

`createContextualFragment` parses HTML and **executes** any `<script>` it contains,
unlike `innerHTML = ...` which does NOT execute inline scripts but does execute
inline event handlers and `<img onerror=...>`. Both run admin-supplied JS. If your
extension exposes a custom-HTML/custom-JS settings field, you've shipped persistent
XSS with admin authorship.

```bash
rg -n "createContextualFragment|insertAdjacentHTML|innerHTML\\s*=" js/src/
```

For each hit, trace the input. If the source is `app.forum.attribute('...')` or a
settings field, the rule is:
- The setting must be `admin-only-editable` (already true for settings).
- The output must be sanitized server-side BEFORE serialization (§9.2 + §21) AND
  mirrored in JS sanitization.
- The settings panel must display a `WARNING — this content executes in every
  visitor's browser` banner. Operators don't always understand that "raw HTML" =
  "stored XSS by admin authorship".

### 47.2 Settings-as-`<script>` — never

```php
// BAD — admin pastes JS, every visitor runs it
(new Extend\Settings())
    ->serializeToForum('myextCustomJs', 'myext.custom_js', null, '')
```

```ts
// BAD — paired frontend
const code = app.forum.attribute('myextCustomJs');
new Function(code)();                                    // or: eval(code)
```

Don't ship this. If your use case is "let admins inject GA / analytics / custom
trackers", offer a dedicated settings field with a fixed shape (`google_analytics_id`,
`matomo_url`) and emit the script tag yourself with a strict allowlist.

### 47.3 `style.innerHTML` and CSS injection

A setting value interpolated into a `<style>` tag's `innerHTML` is **CSS-injection
adjacent**, not stored-XSS — but CSS can exfiltrate text via attribute selectors
hitting attacker-controlled URLs, and `expression()` was a thing on old IE. Treat any
CSS-from-admin-settings with the same suspicion as raw HTML.

```ts
// BAD
const styleEl = document.createElement('style');
styleEl.innerHTML = `.MyExt-tab { height: ${app.forum.attribute('myextTabHeight')}; }`;
document.head.appendChild(styleEl);

// GOOD — coerce to a known shape
const raw = String(app.forum.attribute('myextTabHeight') ?? '');
const px  = /^\d{1,3}(\.\d+)?(px|rem|em|%)?$/.test(raw) ? raw : '48px';
styleEl.textContent = `.MyExt-tab { height: ${px}; }`;
```

Use `textContent`, not `innerHTML`, when assigning to a `<style>` element —
`textContent` does not invoke the HTML parser. And **validate the value against the
narrowest possible regex** before interpolation. Free-text settings flowing into CSS
is a finding regardless of how harmless it looks.

### 47.4 The custom-JS / custom-CSS / custom-HTML settings pattern (when it IS required)

Some extensions exist specifically to give admins these surfaces — a "site
customization" extension is the obvious one. If you must ship this:

1. **Sanitize server-side** in the `serializeToForum` cast (§21) — not just in JS. A
   JS-only sanitizer is bypassed by any mXSS / DOMParser blocklist gap (`<svg>`,
   `<math>`, `<noscript>` foreign-content tricks).
2. **Surface the threat model in the settings UI**: a fixed warning banner above the
   field explaining that the content executes for every visitor.
3. **Restrict the permission** to `administrate` + a dedicated `myext.editCustomCode`
   ability, gated through `Extend\Policy`. Don't piggyback on the generic admin
   permission.
4. **Audit-log every change** to a separate table the operator can review (`who
   changed the custom JS, when, what was the diff`). Persistence of the change is
   the moderator's tripwire.
5. **Subresource Integrity (SRI) for any external CDN URLs** the admin pastes — the
   extension can scan the saved value for `<script src="...">` and either require
   `integrity="..."` or reject.

This is a lot of work. The honest framing in the settings UI is "this is dangerous,
but you asked for it" — never silently expose the surface.

### 47.5 Defense for non-customization extensions that incidentally render admin HTML

If your extension exposes an HTML setting (welcome banner, footer text, custom
embed), use Flarum core's same convention: render via `m.trust` only after
**server-side sanitization** through an allowlist HTML sanitizer (`HTMLPurifier`,
`ezyang/htmlpurifier`, or a hand-written DOMDocument-based sanitizer). The shipped
sanitizer class MUST be wired into the `serializeToForum` cast closure (§21) — a
sanitizer class in `src/Support/` that isn't called from any cast is dead code that
doesn't protect you.

```bash
rg -n "m\\.trust\\(.*forum\\.attribute" js/src/
rg -n "serializeToForum\\([^)]+\\)" extend.php | rg -v "boolVal|intval|HtmlSanitizer|sanitize"
```

For each `m.trust(app.forum.attribute(...))`, the corresponding `serializeToForum`
call must pass a sanitizer cast. If the cast is `null` or missing, that's a critical
finding — the JS-only mirror is one bypass away from stored XSS.

### 47.6 Severity calibration for admin-controlled surfaces

| Surface | Threat model | Severity |
|---|---|---|
| `customJs` settings field, no sanitization, executes in browser | Admin compromise → persistent XSS until admin notices | 🟠 medium (admin pre-req) but with high impact ceiling — flag as high |
| Admin-pasted HTML rendered via `m.trust` without sanitizer | Same as above, slightly narrower exploit class | 🟠 medium |
| `style.innerHTML` interpolation of a free-text setting | CSS-injection / exfil via attribute selectors | 🟡 low |
| `createContextualFragment` of server response in a footer/header injector | Same as `m.trust` of admin HTML | 🟠 medium |
| Server emits inline `<script>` with unescaped PHP values interpolated | Stored XSS by any actor whose value lands in the script | 🔴 high (depends on actor) — see §37 |

### 47.7 Quick checklist

- [ ] No `createContextualFragment` / `new Function(...)` / `eval(...)` consuming admin-controlled strings.
- [ ] No `innerHTML = settingValue` outside of a sanitized pipeline.
- [ ] CSS-from-settings is `textContent`, not `innerHTML`, AND value is regex-validated.
- [ ] Any HTML sanitizer class your extension ships is actually wired into the `serializeToForum` cast closure (not just present in `src/`).
- [ ] Admin custom-code settings carry an inline warning explaining the threat model.
- [ ] Permission to edit admin-execute settings is a dedicated ability, not just `administrate`.

---

## §48. Review report output contract

When the user invokes a code-review workflow on this extension — `/review`,
`/security-review`, "review this branch", "audit this extension", or any equivalent
phrasing — Claude must produce a structured report that mirrors the marketplace's
review surface (the screenshots the operator pastes back from their package page).
This section is the **output contract** for that report.

### 48.1 Trigger

Produce the report when the user explicitly asks for a code review of the extension
or branch:

- `/review`, `/security-review`, `/ultrareview`
- "review this", "audit this", "check this for production", "is this safe to ship?"
- After the user has just merged a release branch and asks "anything I missed?"

Do **not** produce the report unprompted during normal development conversations.
A grep for a single bug or a one-file refactor is not a review.

### 48.2 Ask-before-emit protocol

**The full report is long.** Before emitting it, ask the user one short question:

> "I've finished the review (N findings: X critical / Y high / Z medium / W low,
> verdict: <verdict>). Do you want the full structured report (executive summary +
> findings table + verdict), or just the punch list of fixes?"

Use AskUserQuestion with two clearly-labelled options:
- "Full report" — emit the full §48.4 template.
- "Punch list only" — emit just the findings as a numbered list with severity tags,
  no executive summary or verdict block.

If the user has already pre-confirmed in the same session ("yes, give me the full
report after each review"), skip the question and emit directly. Save that
preference as a feedback memory only if the user repeats it across sessions.

### 48.3 Scoring rubric

Two independent 0–100 scores. **Never reuse the same number for both** — they measure
different things.

#### Quality Score (0–100, higher = better)

Start at 100. Deduct per finding, capped per dimension:

| Severity (§33) | Deduction | Cap per dimension |
|---|---|---|
| 🔴 Critical | −25 | no cap — every critical applies in full |
| 🟠 High | −8 | max −24 (3 highs saturates the high bucket) |
| 🟡 Medium | −3 | max −12 |
| ⚪ Low | −2 | max −6 |
| Informational | 0 | display only — does not affect score |

Cross-dimensional additive cap: a single finding never deducts more than its own
severity weight, regardless of how many dimensions it touches (security + robustness
+ dead code on one bug = one −X, not −3X).

Floor at **20**. Below 20 the score signals "this is scaffolding, not an
extension" — collapse to 20 and emit a single verdict explaining it.

Round to the nearest integer. Show as `<score>/100`.

#### Vibe Coded score (0–100, higher = more AI-generated-looking)

Heuristic-only, not a verdict modifier. Score against these tells:

| Tell | Weight |
|---|---|
| Comments explaining WHAT the code does (not WHY) | +8 |
| Multi-paragraph docstrings on internal helpers | +6 |
| Try/catch around every async call with `console.error` swallow | +5 |
| Variables / functions named with `enhanced`/`utility`/`helper`/`manager` for no reason | +4 |
| Boilerplate `// TODO:` and `// FIXME:` left in the shipped bundle | +4 |
| Repeated near-identical helper across 3+ files (no extraction) | +5 |
| Over-engineered abstraction for a one-call-site need | +6 |
| README full of bullet points that the code doesn't deliver | +10 |
| `as any` / `@ts-ignore` clusters | +4 |
| Excessive emoji in code comments or commit messages | +3 |
| Code structurally clean, terse, named consistently, comments-as-WHY only | −15 |
| Tests present and meaningful (not snapshot-only) | −10 |
| Git log shows iterative commits with real review feedback | −8 |

Floor 0, cap 100. Show as `<score>/100`. The score is informational — do not let it
modify the Quality Score.

### 48.4 Verdict thresholds

| Quality Score | Worst severity | Verdict |
|---|---|---|
| ≥ 80 | No 🔴 critical, no 🟠 high | **Approved, should be safe to use in production.** |
| ≥ 80 | Has 🟠 high | **Approved with concerns, might need some adjustments to be safe to use in production.** |
| 75–79 | Any | **Approved with concerns, might need some adjustments to be safe to use in production.** |
| 50–74 | Any | **Rejected, is too risky to be used in production.** |
| < 50 | Any | **Rejected, is too risky to be used in production.** (plus a one-liner: "this extension is a scaffolding/skeleton — implement the advertised features before re-review" if Quality < 50 and no critical findings.) |

The verdict string is reproduced **verbatim** — the marketplace UI matches on the
exact phrasing.

### 48.5 Executive summary template (3–4 sentences)

Write a tight 3–4 sentence executive summary mirroring the marketplace shape. Each
sentence has a distinct job:

1. **Verdict + production-readiness framing** — "This extension is safe to publish but requires fixes in N high-severity areas before it can be considered production-ready for large communities."
2. **The most impactful finding(s)** — one or two sentences naming the concrete bug, the user-visible failure mode, and the affected blast radius.
3. **Structural quality note** — one sentence on what's GOOD: clean architecture, good test coverage, consistent conventions. Reviewers calibrate severity against structural quality; pretending nothing is good when something is reads as biased.
4. **Performance / scale note** — one sentence on N+1, payload size, expensive sync paths, or "no significant performance concerns".

Keep each sentence under 35 words. No bullet points. The summary is prose, not a
checklist.

**Anti-patterns** in the summary:
- "This extension does X, Y, Z" — that's a description, not a verdict.
- Repeating finding titles verbatim — the table below shows them; the summary should add context.
- Marketing-flavored language — "thoughtfully engineered", "robust", "battle-tested". The reviewer voice is neutral.

### 48.6 Findings table format

Below the summary, emit a Markdown table with **exactly five columns**:

```markdown
| # | Severity | Dimension | Title | One-line impact |
|---|---|---|---|---|
| 1 | 🔴 critical | security | Server-Side Request Forgery via unrestricted URL fetcher | Unauthenticated attacker can probe internal infra and cloud metadata. |
| 2 | 🟠 high | production risk | Migrations on high-traffic core tables | `discussions`, `users`, `discussion_user` ALTERs lock for minutes on large forums. |
| 3 | 🟠 high | robustness | UponUserDeletion passes User as subscription model | Polymorphic subject_type corruption — downstream listeners get the wrong model class. |
| 4 | 🟡 medium | security | Bounty amount passed to Stripe without floor/sign validation | Negative or fractional amounts may trigger Stripe rejections or refunds. |
| 5 | ⚪ low | technical debt | CheckoutController instantiates Handler directly instead of via DI | Hidden dependency; complicates testing and replacement. |
```

#### Severity column

Use the emoji prefix from §33 (`🔴 critical` / `🟠 high` / `🟡 medium` / `⚪ low` /
`ℹ informational`). Never `info` / `inf` / shorthand.

#### Dimension column

Pick **exactly one** dimension per finding. The dimension vocabulary is fixed:

| Dimension | When to use |
|---|---|
| `security` | Exploitable vulnerability or weakened security primitive (XSS, SSRF, IDOR, missing authz, weak crypto). |
| `production risk` | Behavior that breaks for a meaningful fraction of forums at scale (long-running migrations on core tables, OOM under realistic load, queue-worker leaks). |
| `robustness` | Code that handles the happy path but silently fails the unhappy path (swallowed exceptions, missing user-visible error UI, missing null checks, wrong type contracts on polymorphic associations). |
| `conventions` | Diverges from Flarum 2.x patterns documented in this file in a way reviewers and operators will flag (composer constraint mismatches, `Capsule\Manager` usage, missing type hints). |
| `dead code` | Code that doesn't ship value: unused imports, unrendered components, commented-out blocks, stale CSS targeting nothing. |
| `technical debt` | Carrying cost that grows over time but isn't a bug today (PHPStan disabled, helper duplication, `as any` clusters, missing tests). |

If a finding genuinely spans two dimensions, **pick the one with the larger impact**
and mention the other in the one-line impact.

#### Title column

Action-style, ≤ 80 chars. Concrete enough that the operator can grep the codebase
for the bug from the title alone. Examples from the screenshots reproduced verbatim:
- "Migrations on high-traffic core tables"
- "UponUserDeletion passes User as subscription model"
- "GDPR Erasing event dependency not declared in composer.json"
- "ProductResource Index endpoint has no authentication requirement"

#### One-line impact column

One sentence, ≤ 120 chars, describing what breaks for the operator if unfixed. Avoid
restating the title.

### 48.7 Per-finding detail block (optional, after the table)

For each finding ranked 🔴 critical or 🟠 high, follow the table with a short detail
block:

```markdown
#### F2 — Migrations on high-traffic core tables
**Severity:** 🟠 high · **Dimension:** production risk · **Section:** §45

**Where:** `migrations/2026_03_01_000000_add_columns_to_discussions.php:8`,
`migrations/2026_03_05_000000_add_columns_to_users.php:8`, plus three siblings.

**What:** Five migrations issue `Schema::table('discussions'/'users'/'discussion_user', ...)`
adding columns directly to core tables.

**Why it matters:** On a forum with 5 M+ discussion rows, MySQL <8 holds a metadata
lock for the duration of the `ADD COLUMN`. Operators on managed MySQL without
`pt-online-schema-change` will see the forum unresponsive during install.

**Fix:** Move every added column to a companion table (`{ext}_discussion_data` keyed
by `discussion_id`), with `cascadeOnDelete()` FK and the same indexes the original
ALTER carried. See §45.
```

For 🟡 medium and ⚪ low findings, the table row alone is enough — don't pad.

### 48.8 Full report skeleton

When the user picks "Full report", emit in this exact order:

```markdown
## Code review

> Verdict line (verbatim from §48.4)

- **Version:** <git tag, branch name, or "unreleased — HEAD at <sha7>">
- **Reviewed at:** <YYYY-MM-DD HH:mm:ss tz, e.g. "2026-05-15 14:32:00 -03">
- **Quality Score:** <N>/100
- **Vibe Coded:** <N>/100

### Executive summary

<3–4 prose sentences per §48.5>

### Findings

<§48.6 table>

### Details

<§48.7 blocks for every critical and high finding, ordered by severity then by file>

### Suggested fix order

1. <finding #N> — <one-line "do this first because">
2. <finding #M> — ...
```

The "Suggested fix order" block is the single most useful section for the operator
— it converts the report into an actionable backlog. Order by:
1. 🔴 critical first (always);
2. Within a severity, prefer fixes that unblock other fixes (e.g., adding a
   companion table BEFORE rewriting readers);
3. Cheap quality-score wins last (remove `console.log`, drop unused import) so the
   operator can see the score climb between releases.

### 48.9 Output discipline

- **Use the marketplace verbatim phrasings** in §48.4 — the package page renders
  matches on those strings.
- **Reproduce the timestamp in the user's local TZ** if known (memory: `currentDate`).
  If not, use UTC and label it.
- **No invented file paths.** Every "Where:" line must be a path that exists in the
  branch under review. Verify with `Read` or `Glob` before emitting.
- **No invented findings.** If a section of this CLAUDE.md applies but the codebase
  is clean against it, do NOT manufacture a finding to pad the table.
- **No empty findings table.** If there are zero findings, emit:
  > "No findings against this CLAUDE.md's §0–§47 surface. Quality Score: 100/100.
  > Vibe Coded: <score>/100. Verdict: **Approved**, should be safe to use in
  > production."
- **Mirror the example summary's tone** — neutral, observational, structured. No
  "great work!" / "looks good!" / "well done" — reviewer voice is detached.
- **The report is the final output of the review turn.** Don't immediately follow
  with a "next, want me to fix these?" prompt unless the user asked. The report is
  the deliverable; the fix conversation is a separate turn.

### 48.10 Worked example (matches the screenshots the operator shared)

Reproduced here as the canonical shape — when in doubt, copy this layout:

```markdown
## Code review

> **Approved with concerns, might need some adjustments to be safe to use in production.**

- **Version:** 2.0.0-beta.6
- **Reviewed at:** 2026-05-08 03:36:02 UTC
- **Quality Score:** 75/100
- **Vibe Coded:** 18/100

### Executive summary

This extension is safe to publish but requires fixes in two high-severity areas
before it can be considered production-ready for large communities. A bug in
`UponUserDeletion` passes the User model as the subscription's subject model, which
will silently corrupt data for any downstream event listener expecting a Discussion,
Group, or Tag; additionally, five migrations alter the high-traffic `discussions`,
`users`, and `discussion_user` tables, which will cause significant downtime on
large forums. The code is structurally sound, well-tested, and shows clear
architectural intent, but has a handful of correctness and production-safety gaps
that suggest it was not fully exercised under realistic conditions. N+1 queries are
avoided through eager loading of `bountyCurrency` and `tags` relationships, but the
`SubscriptionResource` fetches all Stripe `PaymentIntents` and `Subscriptions` for a
customer in a single `results()` call with no pagination cap, which may be slow for
users with many transactions.

### Findings

| # | Severity | Dimension | Title | One-line impact |
|---|---|---|---|---|
| 1 | 🟠 high | production risk | Migrations on high-traffic core tables | Five `ALTER`s lock `discussions`/`users` for minutes on large forums. |
| 2 | 🟠 high | robustness | UponUserDeletion passes User as subscription model | Polymorphic subject corruption — downstream listeners read the wrong type. |
| 3 | 🟡 medium | dead code | Unused import `TotalBountySelect` | Adds ~2 KB to forum bundle for no rendering. |
| 4 | 🟡 medium | robustness | GDPR Erasing event dependency not declared in composer.json | Extension wires a `Flarum\Gdpr\Events\Erased` listener with no `suggest`/`require` or `class_exists` guard. |
| 5 | 🟡 medium | security | Bounty amount passed to Stripe without floor/sign validation | Negative or zero values reach Stripe; refunds or rejections at the gateway. |
| 6 | 🟡 medium | security | `ProductResource` Index endpoint has no authentication requirement | Unauthenticated users enumerate the product catalog including draft/disabled rows. |
| 7 | ⚪ low | technical debt | `CheckoutController` instantiates Handler directly instead of via DI | Harder to test; hides dependency. |
| 8 | ⚪ low | dead code | Redundant double-check in `Discussions/IsPrivate` | Same guard runs twice on every read. |

### Details

#### F1 — Migrations on high-traffic core tables
**Severity:** 🟠 high · **Dimension:** production risk · **Section:** §45

**Where:** `migrations/2026_03_01_*_add_to_discussions.php:8` and four siblings.

**What:** Five migrations issue `Schema::table('discussions'/'users'/'discussion_user', ...)`.

**Why it matters:** On a forum with 5 M+ rows, MySQL <8 holds a metadata lock for
the duration of `ADD COLUMN`. Install becomes a maintenance window.

**Fix:** Move added columns to companion tables (`bounty_discussion_data` keyed by
`discussion_id`, etc.), with `cascadeOnDelete()` FK. See §45.

#### F2 — UponUserDeletion passes User as subscription model
**Severity:** 🟠 high · **Dimension:** robustness · **Section:** §46.1

**Where:** `src/Listener/UponUserDeletion.php:42`.

**What:** `event(new SubscriptionCancelled($user, $user))` — second arg should be
the subscription's subject model (Discussion/Group/Tag), not the User.

**Why it matters:** Downstream listeners do `instanceof Discussion`/`Group`/`Tag`
checks that never match; cancellation work is silently skipped; the polymorphic
`subject_type` column gets `User::class` written into rows whose `subject_id` is a
discussion ID.

**Fix:** `event(new SubscriptionCancelled($user, $subscription->subject))`.

### Suggested fix order

1. F2 — typed constructor on `SubscriptionCancelled` prevents this whole class of
   bug, and once fixed the existing tests will cover it.
2. F1 — schema change needs a release-coordinated migration; queue for the next
   minor version.
3. F5 — input validation on money is a one-line guard plus a regression test.
4. F6 — add `Endpoint\Index::make()->authenticated()` to `ProductResource`.
5. F4 — add `class_exists(\Flarum\Gdpr\Events\Erased::class)` gate and move
   `flarum/gdpr` to `suggest`.
6. F3, F7, F8 — cosmetic.
```

### 48.11 Calibration anchors

If you find yourself uncertain about a score, anchor against these published reviews:

| Quality | Vibe | Symptoms | Verdict |
|---|---|---|---|
| 32 | 35 | Unauth SSRF + TLS disabled + no rate limiting | Rejected |
| 40 | 20 | Empty skeleton, only `console.log` ships | Rejected |
| 67 | 50 | Multiple highs across security and robustness | Rejected (just barely) |
| 75 | 18 | 2 highs + 4 mediums + 2 lows, otherwise clean architecture | Approved with concerns |
| 77 | 42 | 1 high admin-XSS + 5 mediums, payload bloat | Approved with concerns |
| 80 | 8 | 1 high core-table migration, 2 mediums, otherwise excellent | Approved with concerns |
| 90+ | <15 | One or two lows, no security or robustness issues | Approved |

If your scoring lands materially outside these anchors, re-check the rubric — you
likely under- or over-weighted a finding.

---

## §49. Cryptographic key material persisted in the `settings` table

**CWE-312.** Any private key, HMAC secret, OAuth refresh token, signing seed, or
session-encryption material stored in the `settings` table is **plaintext at rest**.
A SQL injection elsewhere in the stack, a leaked backup, a phpMyAdmin exposure on
shared hosting, or a compromised admin browser session reading the settings page
all surface the secret. The forum's own `password_reset_token` etc. live in
dedicated tables with TTL — `settings` has no such hardening.

### Red flags

```bash
rg -n "settings->set\\(.*key|sign|secret|hmac" src/
rg -n "settings->get\\(.*key|sign|secret" src/
```

Any `Settings::set('myext.sig_key', base64_encode(...))` is the bug.

### Correct shape

1. **Envelope-encrypt before persisting** with XChaCha20-Poly1305 (or AES-GCM)
   using a key derived deterministically from `Flarum\Foundation\Config`. The
   stable per-install inputs are `$config['url']` and `$config['paths']['base']`,
   hashed: `hash('sha256', 'salt|'.$url.'|'.$path, true)`.
2. **Refuse to persist** if the host lacks the AEAD primitive
   (`function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt')`).
   Throwing a RuntimeException with operator-facing instructions is the right
   response — a silent plaintext fallback is the bug being prevented.
3. **Accept legacy plain blobs on read** (so existing installs don't lose their
   key on upgrade) but **rewrite to the envelope format on first decode**, so
   the plaintext doesn't linger past the next read.
4. **Never read an env var.** See §52. Flarum operators don't set `.env`; the
   only persistent install-level configuration source is `config.php` plus the
   `settings` table.

### Anti-patterns that re-introduce the bug

- Reading an env var like `MYEXT_KEY_ENC` and **falling back to plaintext**
  when it's absent. The fallback is the vulnerability.
- Using `random_bytes()` as the envelope key and storing it next to the encrypted
  payload. Persisting both makes the encryption a no-op.
- Symmetric envelope key reused across installs ("hardcoded in the source"). The
  threat model includes attackers who can read your source.

### Reference shape

The marketplace extension's `src/Service/LicenseSigner.php`: plaintext on disk
is impossible — `encode()` throws if libsodium lacks AEAD, and `envelopeKey()`
throws if `Config` has no `url` or `paths.base`.

---

## §50. Synchronous heavy work in request handlers

A controller that calls into a service taking 30+ seconds (archive extraction,
multi-row Stripe sync, image transcoding, multi-step license verification) will
**hit PHP-FPM's `request_terminate_timeout` and leave the system in a partial
state** with no error surfaced to the admin. The upload moved before processing
started, so the raw file lives on disk; the DB row may have been written but
without the post-processing flag; the queue worker, if there is one, never sees
the task. The admin clicks "Save", spinner runs forever, eventually they refresh.

### Locate

```bash
rg -n "set_time_limit|ini_set\\('max_execution_time" src/
rg -n "->process\\(|->extract\\(|->transcode\\(|->resize\\(|->compile\\(" src/Api/Controller/
rg -n "->process\\(|->extract\\(" src/Service/ -l
# For each handler-side hit: is the call surrounded by a queue dispatch?
rg -n "ShouldQueue|::dispatch\\(" src/
```

A controller that calls a heavy service inline and ALSO does not implement
`ShouldQueue` is a finding.

### Correct shape

1. **Persist the record with `processing_status = 'queued'`** as the first DB
   write. The controller returns 201 with the row's ID before the work starts.
2. **Dispatch a job (`implements ShouldQueue`)** that does the heavy work. The
   job updates `processing_status` (`processing` → `ready` | `failed`).
3. **Frontend polls** the resource for status changes; admin sees an
   "in progress" indicator instead of a hung spinner.

```php
class UploadController {
    public function handle(...) {
        $record = MyModel::create([
            ...,
            'processing_status' => 'queued',
        ]);
        ProcessUploadJob::dispatch($record->id, $tempFilePath, $opts);
        return new JsonResponse(['data' => ['id' => $record->id, 'processing_status' => 'queued']], 201);
    }
}

class ProcessUploadJob implements ShouldQueue {
    public int $tries = 1;
    public int $timeout = 600;
    public function handle(MyProcessor $processor) {
        $record = MyModel::find($this->id);
        $record->update(['processing_status' => 'processing']);
        try {
            $processor->process(...);
            $record->update(['processing_status' => 'ready', 'processing_error' => null]);
        } catch (\Throwable $e) {
            $record->update(['processing_status' => 'failed', 'processing_error' => mb_substr($e->getMessage(), 0, 1000)]);
            throw $e;
        }
    }
}
```

### `sync` queue driver caveat

Flarum's default queue driver is `sync` — the job runs **inline** in the request.
Going from `inline call` to `Job::dispatch(...)` doesn't, by itself, eliminate
the timeout risk on a default install — it just moves the code path. The real
async behavior surfaces only when the operator configures a non-sync driver
(`redis`, `database`, `sqs`).

The structural change is still worth it:
- The controller doesn't take ANY return value from the job — it returns
  immediately based on the queued row. Even on `sync`, the response shape is
  consistent with what the async driver delivers.
- Document in the extension README that production deployments must configure a
  real queue driver to get the async benefit.
- Persistence of `processing_status` survives even on `sync` — failures surface
  via the `failed` state instead of as a 500.

### Repush / re-notify pattern

When the heavy work is "tell N other systems about a state change" (license
revocation push, webhook fan-out), pair the dispatcher with a per-record
`notified_at` column and a cooldown:

```php
$cutoff = Carbon::now()->subHours(24);
$pending = Subscription::query()
    ->whereNotNull('license_revoked_at')
    ->whereNotNull('license_domain')
    ->where(fn ($q) => $q->whereNull('revoke_notified_at')->orWhere('revoke_notified_at', '<', $cutoff))
    ->limit(200)
    ->get();
```

Without the `revoke_notified_at` filter, an hourly cron iterating "every
revoked record" grows linearly with the lifetime of the marketplace and ends up
hammering 10,000 endpoints per hour for records that were notified successfully
a year ago. With the filter, work per tick is bounded.

### Stripe-style batch pagination

For "reconcile local state with provider state" jobs, **never fetch per-row**
when the provider exposes a list endpoint. Stripe's
`subscriptions.list(['limit' => 100])` returns a page; the next page is keyed by
`starting_after = $lastItem->id`. Index local records by the provider ID and
intersect with the returned page — one API call per 100 records instead of
per-record.

```php
$locals = Subscription::query()
    ->whereNotNull('stripe_subscription_id')
    ->get()
    ->keyBy('stripe_subscription_id');

$startingAfter = null;
do {
    $page = $stripe->listSubscriptions($startingAfter, 100);
    foreach ($page->data as $remote) {
        if ($local = $locals->get($remote->id)) {
            $this->reconcile($local, $remote);
        }
    }
    $startingAfter = $page->has_more ? end($page->data)->id : null;
} while ($startingAfter !== null);
```

A 6,000-record sync goes from ~60 seconds (per-row) to ~3 seconds (batched).

---

## §51. Estilo de comentário — Flarum core, em PT-BR

Comentários neste codebase seguem **exatamente** a lógica de comentário usada
no core do Flarum e nas extensões oficiais (`flarum/tags`, `flarum/likes`,
`flarum/mentions`, `flarum/suspend`, `flarum/gdpr`). A regra é simples:

> **Só docblocks. Em PT-BR. Curtos. Só onde explica algo que o código não
> consegue dizer sozinho.**

### A diretriz absoluta — sem `//` inline

Esta extensão **não usa** comentários de linha (`//`). Nem em separadores
visuais (`// ── seção ──`), nem em pequenas notas (`// nota`), nem trailing
(`$x = 1; // comentário`). Se algo precisa de explicação, é porque a *unidade*
precisa de docblock — não um pedacinho dela.

Por que esse rigor? O reviewer "vibe-coded" pontua alto qualquer arquivo com
muitos `//` espalhados, e Flarum-core também usa `//` parcimoniosamente. Vetar
totalmente é uma regra mais fácil de auditar e produz código quase
indistinguível do estilo das extensões oficiais.

### Onde Flarum-core coloca docblock — e onde NÃO coloca

Olhando `vendor/flarum/core/src/User/User.php`, `vendor/flarum/tags/src/Tag.php`,
`vendor/flarum/likes/src/Notification/PostLikedBlueprint.php`:

| Local | Tem docblock? | Conteúdo típico |
|---|---|---|
| Modelos Eloquent (classe) | **Sim** | Bloco `@property` puro, sem prose |
| Service / Handler (classe) | **Só se não-óbvio** | 1–4 linhas dizendo *o que* o serviço faz |
| Resource / Endpoint (classe) | Não | O nome já diz tudo |
| Listener (classe) | **Só se há side effect importante** | 1 linha |
| Constantes (`public const`) | **Só se "por que esse valor"** | 1 linha |
| Métodos `boot()`, `getRules()`, hooks framework | **Sim** | 1 linha (`Boot the model.`) |
| Relations (`belongsTo`, `hasMany`) | Não | Self-explicativo |
| Getters/setters triviais | Não | Self-explicativo |
| `@param`/`@return` quando o tipo basta | **Não** | Redundante |
| `@param`/`@return` com array de shape específico | **Sim** | `array{key: type}` |
| Método de regra de negócio com invariante sutil | **Sim** | 1–3 linhas explicando *por quê* |

### A regra concreta

Adicione um docblock quando, e SOMENTE quando, ao menos uma destas for verdade:

1. **A classe é um modelo Eloquent** — coloque um `@property` block.
2. **A classe ou método tem um contrato não-óbvio** — invariante, side-effect,
   retorno em shape específico, ordem de operações importa.
3. **O método é um override de framework** que precisa sinalizar intenção
   (`boot()`, `getRules()`, etc.) — uma linha basta.
4. **A constante tem um valor decidido por razões não-óbvias** — explique em
   uma linha.

Em **todos os outros casos**, o código fica sem comentário. O nome da classe,
o nome do método, a assinatura tipada e a estrutura do código dizem o resto.

### Formato exato

Docblock PT-BR no estilo Flarum:

- Abre com `/**` em linha própria.
- Cada linha de prose: `     * Texto.` (asterisco alinhado, ponto final).
- Linhas em branco internas: `     *`.
- Fecha com `     */` em linha própria.
- 1 a 4 linhas de prose. **Nunca um parágrafo de prose.**
- `@param`/`@return`/`@throws` só quando agregam informação além da signature.
- Imperativo na primeira pessoa do plural ou descritivo na 3ª pessoa, ambos
  aceitos. Sempre verbo de ação na primeira palavra: *"Devolve…"*, *"Cria…"*,
  *"Atualiza…"*, *"Garante…"*, *"Recusa…"*.

### Exemplos lado a lado

**RUIM** — comentários `//` espalhados:

```php
public function process(string $zipPath): array
{
    if (! is_file($zipPath)) {
        throw new \RuntimeException('ZIP não existe');
    }

    // Storage privado em vez de /tmp shared
    $tmpDir = $this->resolveTmpBase() . '/mp_zip_' . bin2hex(random_bytes(8));

    // Validação anti zip-slip
    $hasBackslash = $this->validateZipEntries($zip);

    // Roda apenas após o stripping
    $integrityResult = $this->integrity->inject($extensionRoot);
}
```

**BOM** — sem `//`, docblock no método quando o WHY merece:

```php
/**
 * Pós-processa um ZIP recém-enviado: valida entries, extrai, injeta o stub
 * de licença e re-empacota. Falha em qualquer violação de segurança aborta
 * com `RuntimeException` sem deixar resíduo em disco.
 */
public function process(string $zipPath): array
{
    if (! is_file($zipPath)) {
        throw new \RuntimeException('ZIP não existe');
    }

    $tmpDir = $this->resolveTmpBase() . '/mp_zip_' . bin2hex(random_bytes(8));
    $hasBackslash = $this->validateZipEntries($zip);
    $integrityResult = $this->integrity->inject($extensionRoot);
}
```

**RUIM** — docblock redundante:

```php
/**
 * Devolve o id do usuário.
 *
 * @return int
 */
public function getId(): int
{
    return $this->id;
}
```

**BOM** — sem docblock; o nome + a signature dizem tudo:

```php
public function getId(): int
{
    return $this->id;
}
```

**BOM** — modelo Eloquent com `@property` block:

```php
/**
 * @property int $id
 * @property int $user_id
 * @property string $status
 * @property \Carbon\Carbon|null $current_period_end
 */
class Subscription extends AbstractModel
{
    protected $table = 'marketplace_subscriptions';
    // ...
}
```

**BOM** — método com contrato não-óbvio:

```php
/**
 * Cifra o par Ed25519 com envelope AEAD. Recusa persistir quando o host não
 * suporta a primitiva — fallback plaintext é exatamente o bug evitado.
 */
protected function encode(string $binary): string
{
    // ...
}
```

### O que NUNCA fazer

- Comentário `//` em qualquer forma (standalone, trailing, separador).
- Docblock que só repete o que o nome ou a signature já diz.
- Docblock multi-parágrafo (> 4 linhas de prose). Se precisar disso, vire no
  README ou no PR.
- Referência `CLAUDE.md §X` dentro do código — vira ruído quando a numeração
  muda.
- TODO / FIXME / XXX sem link para uma issue do GitHub.
- `@param string $name` quando a signature já tem `string $name`.

### Lint de disciplina (rode antes de commitar)

```bash
# Qualquer `//` é violação automática.
rg -n '//' src/ extend.php migrations/ | grep -vE '\.com//|http:|https:|ftp:|://[a-z]' | head

# Docblocks com > 5 linhas (potencialmente prose).
rg -nU "^\\s*/\\*\\*\\s*\\n(\\s*\\*[^\\n]*\\n){5,}\\s*\\*/" src/

# Referências CLAUDE.md no código (sempre suspeitas).
rg -n 'CLAUDE\.md' src/ extend.php migrations/
```

Os três comandos devem retornar zero matches num codebase em compliance.

### Quando o nome do método é estrangeirismo

Termos do domínio Stripe (`webhook`, `checkout`, `subscription`, `refund`),
de pacotes (`composer`, `package`), de framework (`middleware`, `policy`,
`extender`) **continuam em inglês** dentro da prose PT-BR. Não traduza
"webhook" para "gancho", nem "refund" para "reembolso de pagamento". O leitor
do código é um dev que conhece o vocabulário; forçar a tradução prejudica a
leitura.

```php
/**
 * Constrói a Stripe Checkout Session em modo subscription.
 */
public function createSubscriptionSession(Order $order): StripeSession
```

### O que esta seção NÃO é

- Não é "delete todo comentário". Docblocks que pagam aluguel ficam.
- Não é "reescreva CLAUDE.md no PHP". O playbook serve para o autor antes de
  escrever, não para o runtime.
- Não é retroativo em contratos de framework. Docblocks de override (`boot()`)
  e PSR-3 ficam onde o framework espera.

---

## §52. No env vars in extensions — use `config.php` and the settings table

Flarum doesn't read `.env`. The operator configures the install through
`config.php` (debug mode, paths, mail driver, queue driver, trusted proxies)
and the admin UI / `settings` table (everything else). Extensions follow the
same contract. **`getenv()`, `$_ENV`, and `$_SERVER['HTTP_*']` reads from an
extension are an automatic finding.**

### Why the rule is absolute

- Operators don't expect to set env vars for forum extensions; the install
  docs don't tell them to. A "you must export FOO=bar" requirement is the
  bug, not the feature.
- Shared hosting often has no shell access; env vars there require server
  reconfiguration the operator can't do.
- Docker entrypoints that build images upstream don't carry per-install
  secrets; env-var dependencies break on container redeploy.
- PHP-FPM pools inherit env from the master, which is set at service start —
  changing an env var requires a restart, not a config reload.

### Where each setting belongs

| Concern | Goes in | How to read |
|---|---|---|
| Debug / verbose output | `config.php` `'debug' => true` | `app(Flarum\Foundation\Config::class)['debug']` |
| Forum URL | `config.php` `'url'` | `$config['url']` or `app('flarum.config')->url()` |
| DB credentials | `config.php` `'database'` | `$config['database']` |
| Trusted reverse proxies | `config.php` `'trustedProxies'` | resolved by core middleware |
| Per-install secret derivation | `config.php` (`url` + `paths.base`) | KDF: `hash('sha256', ...)` |
| Stripe API keys, mail SMTP, etc. | admin UI → `settings` table | `SettingsRepositoryInterface::get(...)` |
| Per-actor preferences | `users.preferences` JSON | `$user->preferences['x']` |

### Gating console commands on debug mode

```php
// extend.php
$boot = Support\BootSettings::load();

(function () use ($boot) {
    $console = (new Extend\Console())
        ->command(Console\SyncLicensesCommand::class);

    if ($boot->debugMode()) {
        $console = $console
            ->command(Console\DebugPackagesCommand::class)
            ->command(Console\DebugShopPathCommand::class);
    }
    return $console;
})()
```

`Support\BootSettings` (a small per-install snapshot helper) reads the Config
once at extender-build time, caches `debug`, and exposes `debugMode(): bool`.
Centralizes the try/catch + cache pattern so the rest of the extension never
calls `resolve(Config::class)` directly.

### Anti-patterns

- `getenv('MYEXT_DEBUG') === '1'` — reads from PHP-FPM env, not `config.php`.
- `$_ENV['MYEXT_KEY']` — same as above plus inconsistent across SAPI (cli vs
  fpm read different files).
- `putenv()` inside a service provider — pollutes the worker process for
  every subsequent request.
- Reading config from `getenv` and the settings table for the *same* setting —
  one always wins, and the operator can't tell which.

### Migration path when an extension already reads env

If a deprecated env var is in production use, support both for one minor
version: read settings/Config first, fall back to env with a deprecation
warning logged. Drop the env path in the next breaking release. Don't add
new env reads.

### Quick audit

```bash
rg -n "getenv\\(|\\\$_ENV\\[|\\\$_SERVER\\['HTTP_" src/
# Every hit must be removed or replaced with Config / SettingsRepository.
```

---

## §53. Handlers gordos — quebre `handle()` quando passar de ~100 linhas

Um `RequestHandlerInterface::handle()` (ou `AbstractCommand::fire()`) acima de
~100 linhas é sinal automático de refator. Não importa quantas validações
encadeadas existem — o controller é o lugar errado para conter regra de
negócio. Reviewers chamam de "god method" e a pontuação cai sozinha porque
qualquer correção no fluxo exige reler 500 linhas de lógica encadeada.

### Threshold concreto

- **`handle()` ≤ 100 linhas**: aceitável.
- **`handle()` 100–200 linhas**: refator desejável; planeje na próxima
  iteração tocando o arquivo.
- **`handle()` > 200 linhas**: bloqueante. Refator antes de merge.

A contagem inclui closures internas. `try/catch` envolvendo um bloco grande
conta como "uma linha" só se o bloco TODO está extraído para outro método.

### Onde extrair

| Tipo de bloco | Para onde extrair |
|---|---|
| Cascata de "se X então 422" antes do work | `Service\<Domain>\<Domain>Gate` |
| Sanitização + required-check de payload | `Service\<Domain>\<Field>Validator` |
| Resolução de regra com várias dependências | `Service\<Domain>\<X>Resolver` |
| Criação atômica de N rows com transação | `Service\<Domain>\<X>Builder` ou `<X>Factory` |
| Decisão de branch (free vs Stripe vs offline) | métodos `finalize*` no próprio controller |

O controller fica como orquestrador: recebe `ServerRequestInterface`, chama
gate, valida, despacha para o builder, devolve `JsonResponse`. Cada serviço
extraído fica testável isoladamente.

### Exemplo do split aplicado

O `CreateCheckoutController` original tinha 569 linhas, `handle()` com ~530.
Após refator: 276 linhas no controller, `handle()` com ~140; três serviços em
`src/Service/Checkout/`:

```
src/Service/Checkout/CheckoutGate.php          (135 linhas — gates de acesso)
src/Service/Checkout/BillingValidator.php      ( 49 linhas — sanitize + required)
src/Service/Checkout/CheckoutOrderBuilder.php  (186 linhas — Order + items + activations)
```

O controller orquestra:

```php
public function handle(ServerRequestInterface $request): ResponseInterface
{
    $items = $this->cart->items($request);
    if ($err = $this->gate->check($request, $items)) {
        return new JsonResponse($err, $err['http'] ?? 422);
    }

    $billing = BillingValidator::sanitize($body['billing'] ?? []);
    if ($missing = BillingValidator::missingField($billing, $items)) {
        return new JsonResponse(['error' => 'missing_field', 'field' => $missing], 422);
    }

    $order = $this->builder->build($items, $billing, /* ... */);

    return $this->finalizeStripe($order, /* ... */);
}
```

### Anti-padrões

- **Refator que só renomeia métodos protegidos no mesmo controller.** Manter
  todos os métodos no controller não resolve — fica um controller de 600
  linhas em vez de 530. O ponto é extrair para classes injetáveis.
- **Reservation/transação fora do builder.** Se a transação está num método
  do controller, qualquer exception no caminho vaza a reserva (de cupom, de
  pool). A transação MORA no builder; o controller chama `releaseReservation`
  no catch.
- **Validator estático puxando settings.** Validator é static utility — não
  injeta dependências. Se precisa de settings, é gate (instanciável), não
  validator.

### Audit lint

```bash
rg -nU "public function (handle|fire|process)\\(.*?\\): [A-Za-z]+\\s*\\{" --type=php src/ -A 200 \
  | rg "^\\s*\\}" -B 200 | awk '/public function (handle|fire|process)/{c=0} {c++; print}'
```

(Use seu IDE — qualquer ferramenta que conte linhas por método serve.)

---

## §54. Laravel Filesystem vs PHP nativo

Funções nativas de filesystem (`file_get_contents`, `file_put_contents`,
`mkdir`, `unlink`, `rename`, `scandir`, `is_file`) **devem ser a exceção**.
A regra default é `Illuminate\Contracts\Filesystem\Factory` injetado, com a
extensão registrando seu disco via `Extend\Filesystem`.

### Quando a exceção é legítima

| Ferramenta nativa | Quando não há alternativa Flysystem |
|---|---|
| `ZipArchive` | Flysystem não tem API de zip — precisa de path real |
| `php_strip_whitespace` | Aceita só um arquivo path nativo |
| `pcntl_*`, `posix_*` | Não há disco envolvido — é processo |
| `RecursiveDirectoryIterator` sobre dir extraído | Iteração estrutural local, pré-pipeline |
| `tempnam` / `sys_get_temp_dir` | **Não**: use `Flarum\Foundation\Paths::storage` |

### Padrão correto quando você precisa de paths reais

Mesmo nos casos legítimos da tabela acima, a `Paths` do Flarum vem por
injeção (nunca via `resolve()` inline ou `sys_get_temp_dir`):

```php
class ZipPostProcessor
{
    public function __construct(
        protected LoggerInterface $logger,
        protected LicenseSigner $signer,
        protected Paths $paths,
    ) {
    }

    protected function resolveTmpBase(): string
    {
        $base = $this->paths->storage . '/marketplace/.tmp';
        if (! is_dir($base)) {
            @mkdir($base, 0700, true);
        }
        return is_writable($base) ? $base : sys_get_temp_dir();
    }
}
```

`sys_get_temp_dir()` fica APENAS como fallback de último recurso (host com
storage não-gravável); em produção real, sempre cai no path de
`paths->storage`. Em shared hosting, `/tmp` é compartilhado com tenants
vizinhos — TOCTOU sobre arquivos por lá é uma classe inteira de bug.

### Quando NÃO é exceção legítima

- **Servir arquivos para download**: use `$disk->readStream($path)` →
  `Laminas\Diactoros\Stream` (§38.2 cobre).
- **Persistir uploads de admin**: use `$disk->putFileAs(...)`. O finding 11
  (uploads) já dita o pipeline; native `move_uploaded_file` é o que
  `UploadedFileInterface::moveTo` faz por baixo, mas a API correta é
  `getStream()` + `$disk->writeStream($stream)`.
- **Cache de blobs derivados**: registre um disco dedicado (`mp-cache`) via
  `Extend\Filesystem`; o cleanup vira `$disk->deleteDirectory($prefix)`.

### Audit lint

```bash
rg -nE '(file_get_contents|file_put_contents|fopen|fwrite|mkdir|unlink|rename|scandir|copy|is_file|is_dir|realpath|tempnam|sys_get_temp_dir)\(' src/
# Cada hit fora de Service/ZipPostProcessor.php, Service/IntegrityInjector.php
# e LicenseObfuscator (todos legítimos por ZipArchive) precisa virar Filesystem.
```

---

## §55. Pinning de versão de SDK externo

Fixar `Stripe::setApiVersion('2025-02-24.acacia')` enquanto o `stripe-php`
^20 tem default `2026-04-22.dahlia` é uma armadilha técnica reconhecida:

1. **Stripe deprecia versões antigas** com prazo público. Quando seu pin
   atingir EOL, o webhook quebra silenciosamente — `signature mismatch` ou
   `unknown event type`.
2. **Você perde melhorias de segurança/confiabilidade** das versões mais
   novas (mudanças no shape de `Subscription.items[].current_period_*` da era
   basil, por exemplo).
3. **Compat se acumula**: cada nova versão do SDK que você instala precisa
   ser regredida ao shape antigo.

### Padrão correto

**Não fixe a versão. Em vez disso, escreva uma camada de compat para os
campos cujo shape mudou.**

```php
class StripeCheckout
{
    public const STRIPE_API_VERSION = '';

    protected function configure(): void
    {
        Stripe::setApiKey($this->settings->get('marketplace.stripe_secret_key'));
        if (self::STRIPE_API_VERSION !== '') {
            Stripe::setApiVersion(self::STRIPE_API_VERSION);
        }
    }
}
```

Os pontos que dependem da forma dos campos passam por um helper
`StripeCompat` que lê ambos os shapes:

```php
class StripeCompat
{
    public static function periodEnd(StripeSubscription|StripeObject|array|null $sub): ?int
    {
        $sub = self::asObj($sub);
        $items = $sub?->items?->data ?? null;
        if (is_array($items) && isset($items[0]?->current_period_end)) {
            return (int) $items[0]->current_period_end;
        }
        return isset($sub?->current_period_end) ? (int) $sub->current_period_end : null;
    }

    public static function invoiceSubscriptionId(StripeObject|array|null $invoice): ?string
    {
        $invoice = self::asObj($invoice);
        $nested = $invoice?->parent?->subscription_details?->subscription ?? null;
        if (is_string($nested) && $nested !== '') return $nested;
        $top = $invoice?->subscription ?? null;
        return is_string($top) && $top !== '' ? $top : null;
    }
}
```

Vantagens:

- Webhooks **em flight** no shape antigo continuam tratáveis durante deploy.
- Bump do SDK não é mais bloqueante — só atualiza o `composer.json`.
- Migrar para a nova API é uma decisão deliberada com PR isolado; quando
  todo consumidor da Stripe usa o compat, remover o pin é trivial.

### Generalizar para outros SDKs

| SDK | Campo que muda entre versões | Onde colocar compat |
|---|---|---|
| `stripe/stripe-php` | `subscription.current_period_*`, `invoice.subscription` | `Service/StripeCompat.php` |
| AWS SDK (S3/SES) | retornos `Result` vs `array` | `Service/AwsCompat.php` |
| `paypalhttp/paypal-checkout-sdk` | shapes de Order v1 vs v2 | `Service/PaypalCompat.php` |
| `firebase/php-jwt` | `decode()` argumentos posicionais | `Service/JwtCompat.php` |

A regra: **se o SDK tem um padrão público de major-version bump com breaking
changes na resposta da API, você precisa de uma classe `<SDK>Compat`.**

### Quando pinning é OK

- Versão major do SDK pinned no `composer.json` (`"stripe/stripe-php": "^20"`).
- Algoritmo criptográfico pinned (`hash('sha256', ...)`) — esses sim devem
  ser explícitos.
- DB driver versão minor para reprodutibilidade (`"mysql" => "^8.0"`).

### Quando pinning é débito técnico

- API version de SaaS externo (Stripe, Twilio, Mailgun, etc.) pinned sem
  compat layer.
- `composer.lock` com lib desatualizada há > 1 ano sem motivo.
- Comentário "TODO: migrate when we have time" sem ticket.

---

## §56. Webhook handlers — despachar o job, nunca processar inline

Provedores externos (Stripe, GitHub, Twilio, Mailgun) impõem **deadlines de
resposta no handler** — Stripe declara 30 segundos, depois marca a tentativa
como falhada e reenfileira o evento. Se o controlador:

1. Persiste o evento no banco (`webhook_events` com `event_id` único),
2. Verifica a assinatura HMAC,
3. **E chama o processador inline** (`$this->processor->process($event)`),

a primeira execução longa (e-mail SMTP, claim de digital asset, sync para
Stripe API) estoura o budget. Stripe reenvia. A segunda execução talvez
acerte a dedup, mas **efeitos colaterais executados antes da falha não são
revertidos automaticamente** — cupom já consumido, asset já marcado como
claimed, e-mail já enviado.

### Anti-padrão recorrente: "job fully built, never dispatched"

A revisão de Maio/2026 (branch `BC`) encontrou:

- `ProcessStripeEventJob` definido com `$tries=3`, `$timeout=120`,
  `handle()` completo, retry logic, dedup por `event_id`;
- `StripeWebhookController::handle()` chamando `$this->processor->process($event)`
  **inline** — o `::dispatch()` da classe Job não existe em parte alguma
  do código base.

Esse é um sintoma de "passada final de fiação ficou incompleta" — alguém
construiu a abstração assíncrona mas esqueceu de comutá-la. Pesquise sempre:

```bash
# Qualquer Job\... que NÃO aparece em ::dispatch(...) é morto ou inacabado.
rg -nE 'class\s+(\w+Job)\s+implements\s+ShouldQueue' src/Job/ | awk -F: '{print $NF}' | while read j; do
  name=$(echo "$j" | grep -oE '\w+Job')
  count=$(rg -c "${name}::dispatch" src/ || echo 0)
  echo "$name dispatched: $count"
done
```

### A armadilha do `Dispatchable` (incidente real Maio/2026)

A documentação do Laravel ensina:

```php
use Illuminate\Foundation\Bus\Dispatchable;

class MyJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, SerializesModels;
}

MyJob::dispatch($id);
MyJob::dispatchSync($id);
MyJob::dispatchAfterResponse($id);
```

**Esse trait não existe em Flarum 2.** O pacote `illuminate/foundation`
nunca é instalado — Flarum tem sua própria foundation
(`flarum/core/src/Foundation`). O autoloader só descobre o trait ausente
*quando alguém invoca um método estático que dispara o carregamento da
classe do Job*. Resultado típico:

1. Job class é escrita com `use Illuminate\Foundation\Bus\Dispatchable;`.
2. CI / testes unitários estáticos passam (`assertStringContainsString('use Dispatchable', $jobFile)`).
3. Nada chama `MyJob::dispatch()` por meses.
4. Alguém finalmente conecta: `MyJob::dispatch($id);`.
5. Webhook responde **HTTP 500** com `code:unknown`.
6. Stripe interpreta 500 como retry-worthy. Toda nova ordem fica `pending`
   porque o webhook sempre 500a.
7. Stack trace só visível em logs do servidor (ou response body em modo
   debug): `Error: Trait "Illuminate\Foundation\Bus\Dispatchable" not found`.

### Forma correta — injetar `Bus\Dispatcher`, usar `Queueable`

Padrão idêntico ao `flarum/core/src/Api/Controller/CreateTokenController.php`:

```php
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;

class ProcessStripeEventJob implements ShouldQueue
{
    use Queueable, InteractsWithQueue, SerializesModels;

    public int $tries = 3;
    public int $timeout = 120;

    public function __construct(public int $eventRowId) {}

    public function handle(EventProcessor $processor, LoggerInterface $logger): void { /* ... */ }
}
```

```php
use Illuminate\Contracts\Bus\Dispatcher as BusDispatcher;

class StripeWebhookController
{
    public function __construct(
        protected StripeCheckout $stripe,
        protected LoggerInterface $logger,
        protected BusDispatcher $bus,
    ) {}

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        try {
            $event = $this->stripe->constructEvent($payload, $sigHeader);
        } catch (SignatureVerificationException $e) {
            return new JsonResponse(['error' => 'invalid_signature'], 400);
        }

        $row = $this->persistEvent($event, $payload);
        if ($row && $row->processing_status === 'done') {
            return new JsonResponse(['received' => true, 'deduped' => true]);
        }

        if ($row) {
            try {
                $this->bus->dispatchSync(new ProcessStripeEventJob($row->id));
            } catch (\Throwable $e) {
                $this->logger->error('[marketplace] webhook job throw: '.$e->getMessage(), [
                    'event_id' => $event->id,
                    'trace'    => $e->getTraceAsString(),
                ]);
                return new JsonResponse(['received' => true, 'processed' => false], 200);
            }
            return new JsonResponse(['received' => true]);
        }

        return $this->processWithoutAuditRow($event);
    }
}
```

Pontos críticos:

- **`Queueable`** (de `illuminate/bus`) substitui `Dispatchable` (que não
  existe). É o mínimo necessário para satisfazer `ShouldQueue` e os hooks
  de retry/middleware. Pacote `illuminate/bus` é shipped por Flarum.
- **`Bus\Dispatcher` injetado** no construtor. Flarum registra a binding em
  `Flarum\Bus\BusServiceProvider`.
- **`$this->bus->dispatchSync(new $job)`** sempre roda inline — não depende
  de driver de queue nem de worker do operador.
- **`try/catch` em volta do dispatch** absorve falhas e responde 200. Se
  voltasse 500, a Stripe retentaria infinitamente e amplificaria o problema.

### Tabela de comportamento das APIs de dispatch em Flarum 2

| Forma | Funciona em Flarum 2? | Observação |
|---|---|---|
| `MyJob::dispatch($id)` via trait `Dispatchable` | **Fatal** — trait não existe | `Trait "Illuminate\Foundation\Bus\Dispatchable" not found` |
| `MyJob::dispatchSync($id)` via trait | **Fatal** — mesmo motivo | idem |
| `MyJob::dispatchAfterResponse($id)` via trait | **Fatal** — mesmo motivo | idem |
| `$this->bus->dispatch(new MyJob($id))` (injetado) | Funciona, mas enfileira | Precisa de queue worker do operador rodando |
| `$this->bus->dispatchAfterResponse(new MyJob($id))` (injetado) | **Cai silenciosa** | `Container::terminating()` em Flarum é no-op (`@deprecated`) |
| `$this->bus->dispatchSync(new MyJob($id))` (injetado) | **Sempre roda** | Latência adicionada à resposta; padrão correto para webhooks |
| `$this->processor->process($event)` inline (sem job) | Funciona | Perde audit row, retry, e a estrutura |

### Caveat de latência

`dispatchSync` adiciona ao tempo de resposta. Para o webhook da Stripe:

- Budget: 30 segundos.
- Processamento atual (e-mail SMTP + asset claim + refund eventual): ~1–3s.
- Margem confortável; se algum dia ultrapassar, o operador configura queue
  worker e troca para `$this->bus->dispatch(new $job)`.

A vantagem do shape com Job + Bus injetado é justamente essa: a troca é
uma única linha no controller; não precisa refatorar a lógica.

### Lint estático que pega esse bug ANTES do deploy

```bash
rg -nE 'use\s+Illuminate\\\\Foundation' src/ vendor/ramon/*/src/ 2>/dev/null \
  | grep -v 'vendor/illuminate/' \
  | grep -v 'vendor/laravel/'
```

Qualquer match em `src/` de uma extensão Flarum é **bug fatal aguardando
para ser disparado**. Pacote `illuminate/foundation` é exclusivo do Laravel
Framework e nunca aparece como dependência do `flarum/core`.

Outra checagem barata: carregar a classe e tentar `reflect`-ar antes de
deployar.

```php
class_exists(\Ramon\Marketplace\Job\ProcessStripeEventJob::class, true);
```

Se o trait estiver faltando, isso lança no momento do load — visível em
qualquer health check.

### Caveat de latência

`dispatchSync` adiciona ao tempo de resposta. Para o webhook da Stripe:

- Budget: 30 segundos.
- Processamento atual (e-mail SMTP + asset claim + refund refund eventual): ~1–3s.
- Margem confortável; se algum dia ultrapassar, o operador configura queue worker e troca para `::dispatch`.

A vantagem do shape com Job é justamente essa: a troca é uma única linha
no controller; não precisa refatorar a lógica.

### Casos relacionados (não-Stripe)

| Origem | Deadline conhecido | Quê dispatch'ar |
|---|---|---|
| GitHub webhook | 10s (com retry) | `ProcessGithubEventJob` |
| Mailgun events | sem deadline rígido, mas 5xx → backoff | `ProcessMailgunEventJob` |
| Twilio status callback | 15s | `ProcessTwilioStatusJob` |
| PayPal IPN/Webhook | 20s | `ProcessPaypalEventJob` |

### Checklist

- [ ] Toda classe `*Job` em `src/Job/` tem ao menos um `::dispatch(` em outro arquivo.
- [ ] `*WebhookController::handle()` retorna `200` em < 500ms no path feliz.
- [ ] A business logic está no Job, não no controlador.
- [ ] Persistência do evento (com unique index em `event_id`) acontece ANTES
      do dispatch — replays do provedor não disparam jobs duplicados.

---

## §57. Token domain binding — cabeçalho ausente não é "dev mode"

Quando um token (composer auth, marketplace API key, license key) declara
um `bound_domain` para vinculá-lo a um servidor específico, a regra é
explícita: **token ligado a domínio só funciona desse domínio**. A
implementação parece simples — comparar o header recebido com o campo
persistido — mas tem armadilhas semânticas.

### Anti-padrão: tratar `''` como dev hint

```php
class ComposerAuth
{
    private const DEV_DOMAIN_HINTS = ['localhost', '127.0.0.1', '.test', '.local', ''];

    private function detectDomain(ServerRequestInterface $request): string
    {
        return $request->getHeaderLine('X-MP-Domain');              // string vazia se ausente
    }

    private function isDevDomain(string $domain): bool
    {
        foreach (self::DEV_DOMAIN_HINTS as $hint) {
            if ($domain === $hint || str_contains($domain, $hint)) return true;   // ← '' bate em qualquer string
        }
        return false;
    }

    public function checkAndBindDomain(Token $token, ServerRequestInterface $request): bool
    {
        $domain = $this->detectDomain($request);
        if ($this->isDevDomain($domain)) return true;               // ← bypass total
        if ($token->bound_domain === null) {
            $token->bound_domain = $domain;
            $token->save();
            return true;
        }
        return $token->bound_domain === $domain;
    }
}
```

Qualquer cliente que **omita `X-MP-Domain`** (o `composer` padrão sem
configuração custom, qualquer `curl` ad-hoc, qualquer proxy que strip
custom headers) ignora a verificação. O binding fornece **falsa
sensação de segurança**.

### Forma correta

Duas correções, na ordem de preferência:

**1. Header de domínio é obrigatório quando o token tem binding.**

```php
public function checkAndBindDomain(Token $token, ServerRequestInterface $request): bool
{
    $declared = trim($request->getHeaderLine('X-MP-Domain'));

    // Binding já existe — header tem que estar presente E bater.
    if ($token->bound_domain !== null) {
        if ($declared === '') return false;                         // ← rejeita ausência
        return strcasecmp($token->bound_domain, $declared) === 0;
    }

    // Primeiro uso — só faz bind se o domínio for derivável.
    $bind = $declared !== '' ? $declared : $this->fallbackFromHost($request);
    if ($bind === null) return false;
    $token->bound_domain = $bind;
    $token->save();
    return true;
}
```

**2. Fallback determinístico: use o `Host` header da requisição.**

```php
private function fallbackFromHost(ServerRequestInterface $request): ?string
{
    $host = parse_url((string) $request->getUri(), PHP_URL_HOST) ?: $request->getHeaderLine('Host');
    $host = preg_replace('/:\d+$/', '', (string) $host);
    return $host !== '' ? strtolower($host) : null;
}
```

O `Host` chega em **toda** requisição HTTP/1.1 — não tem como omitir sem
quebrar o protocolo. Usar `Host` torna o binding **sempre** verificável,
inclusive em clientes "burros" como `composer` sem custom headers.

**3. Limpe a lista de "dev hints".**

`''` nunca deve ser dev hint — string vazia é "header ausente", não
"localhost". E mesmo `localhost`/`127.0.0.1` precisam matchear *exato*,
não `str_contains` (caso contrário `127.0.0.1.evil.com` passa).

```php
private function isDevDomain(string $domain): bool
{
    $domain = strtolower(trim($domain));
    if ($domain === '') return false;                               // ← chave da correção
    return in_array($domain, ['localhost', '127.0.0.1', '::1'], true)
        || str_ends_with($domain, '.test')
        || str_ends_with($domain, '.local');
}
```

### Modelo de ameaça que o binding precisa cobrir

| Cenário | Sem o binding correto | Com o binding correto |
|---|---|---|
| Atacante exfiltra `auth.json` de um cliente | Usa o token de qualquer IP | Token só vale do `Host` original |
| Cliente debugando com curl sem custom header | `''` → dev hint → bypass | Falha; obriga-o a passar `--header "Host: ..."` (que `curl` envia por default) |
| Cliente migrando para novo servidor | Bind silenciosamente troca para o novo host | Bind continua amarrado; obriga issuance de novo token (auditável) |

### Checklist

- [ ] `DEV_DOMAIN_HINTS` não contém `''`.
- [ ] `str_contains` em comparação de domínio foi substituído por `===`,
      `str_ends_with`, ou matching de FQDN exato.
- [ ] Quando o header de domínio está ausente, há fallback para `Host`
      ou rejeição explícita — nunca "permitir".
- [ ] Logs de auth incluem `(bound_domain, declared_domain, host)` para
      forense.

---

## §58. Timestamps de migração devem ser únicos

Laravel ordena migrações **alfabeticamente pelo nome do arquivo**. Quando
dois arquivos compartilham o mesmo prefixo de timestamp
(`2026_04_24_000007_add_screenshots.php` e
`2026_04_24_000007_create_versions.php`), o desempate vira **filesystem
sort** — comportamento indefinido entre Linux (ext4/btrfs), macOS (APFS) e
Windows (NTFS).

### Sintomas em produção

- Em dev (NTFS), `nullable_digital_file` roda antes de `create_digital_versions`
  e altera uma coluna que ainda não existe → fatal.
- Em CI (ext4), a ordem inverte e tudo passa.
- Cliente em produção (CentOS, ext4) também passa.
- Cliente em produção (Ubuntu, btrfs) falha.
- Bug irreprodutível para o autor; relatórios contraditórios.

### Locate

```bash
# Lista timestamps duplicados nos arquivos de migração da extensão.
ls migrations/ | awk -F_ '{print $1"_"$2"_"$3"_"$4}' | sort | uniq -d
```

Qualquer linha de saída é um finding.

### Correção pré-release

Se a extensão **ainda não foi instalada por nenhum cliente**, renomeie os
arquivos para timestamps únicos (com incremento sequencial):

```text
2026_04_24_000007_add_product_screenshots.php   → 2026_04_24_000007_*
2026_04_24_000007_create_digital_versions.php   → 2026_04_24_000008_*
2026_04_24_000008_nullable_digital_file.php     → 2026_04_24_000009_*
2026_04_24_000008_other.php                     → 2026_04_24_000010_*
```

E **garanta** que a renomeação respeita a dependência de schema — a
migração que **cria** a tabela/coluna sempre roda antes da que a
**modifica**.

### Correção pós-release

Se a extensão já foi instalada, **não renomeie os arquivos antigos** —
Laravel armazena o `migration` filename na tabela `migrations`, e
renomear faz com que o instalador re-rode a migração e quebre. Em vez
disso:

1. Deixe os arquivos com timestamp duplicado como estão (instalações
   existentes já passaram da fase crítica).
2. Adicione uma **migração de reparo idempotente** com timestamp
   posterior, que aplica o estado final desejado caso o sistema-de-arquivos
   de algum cliente novo tenha rodado na ordem errada:

```php
<?php
use Flarum\Database\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Schema\Builder;

return [
    'up' => function (Builder $schema) {
        if (! $schema->hasTable('digital_versions')) {
            // Reproduz o create completo aqui, com hasTable guard.
            return;
        }
        if ($schema->hasTable('digital_versions') && ! $schema->hasColumn('digital_versions', 'digital_file_id')) {
            $schema->table('digital_versions', function (Blueprint $t) {
                $t->unsignedInteger('digital_file_id')->nullable();
            });
        }
    },
    'down' => fn () => null,
];
```

O guard `hasTable`/`hasColumn` torna a migração **safe-to-rerun** e
neutraliza o estado divergente.

### Política preventiva

- Use **timestamp com segundos** (`2026_04_24_143205`) em vez de
  `_000007`. Colisão fica praticamente impossível.
- Inclua um teste de CI que falhe quando dois arquivos compartilharem
  prefixo:

```bash
test "$(ls migrations/ | awk -F_ '{print $1\"_\"$2\"_\"$3\"_\"$4}' | sort | uniq -d | wc -l)" = "0"
```

### Cross-reference

[[feedback_flarum_migrations]] — closure migrations já têm `hasTable`/
`hasColumn` guards; estender essa disciplina para timestamps únicos é a
mesma família de robustez.

---

## §59. Verificação HMAC deve devolver o modelo resolvido

Quando uma camada de assinatura precisa do segredo da chave da licença
para validar o HMAC, ela faz um lookup no banco
(`Subscription::where('license_key', $key)->first()`). **Esse modelo já
está em memória** quando a verificação retorna. Se o controlador
imediatamente consulta o mesmo modelo de novo, é uma **query duplicada
em cada request**.

### Anti-padrão (revisão Maio/2026)

```php
// src/Service/License/InboundSignature.php
class InboundSignature
{
    public function verify(ServerRequestInterface $request): array
    {
        $key = $request->getHeaderLine('X-License-Key');
        $secret = $this->resolveSharedSecret($key);                 // ← query 1+2
        // ...HMAC compare...
        return ['valid' => true, 'license_key' => $key];            // ← descarta o modelo
    }

    private function resolveSharedSecret(string $key): ?string
    {
        if ($sub = Subscription::where('license_key', $key)->first()) {     // query 1
            return $sub->shared_secret;
        }
        if ($item = OrderItem::where('license_key', $key)->first()) {       // query 2
            return $item->shared_secret;
        }
        return null;
    }
}

// src/Api/Controller/CheckLicenseController.php
class CheckLicenseController
{
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $result = $this->signature->verify($request);

        // ← MESMA query, segunda vez:
        $subscription = Subscription::with(['user', 'product'])
            ->where('license_key', $result['license_key'])->first();         // query 3
        $orderItem    = OrderItem::with(['order', 'product'])
            ->where('license_key', $result['license_key'])->first();         // query 4
        // ...
    }
}
```

Com 100 extensões instaladas chamando `/license/check` a cada page load,
isso vira **400 queries/min por sessão**. O endpoint público é caminho
quente — não dá para tolerar redundância.

### Forma correta

A camada de assinatura **devolve o modelo já resolvido**. O controlador
faz só o eager-loading adicional necessário (relations).

```php
class InboundSignature
{
    /**
     * @return array{valid: bool, license_key: string, model: Subscription|OrderItem|null}
     */
    public function verify(ServerRequestInterface $request): array
    {
        $key = $request->getHeaderLine('X-License-Key');
        $model = Subscription::where('license_key', $key)->first()
              ?? OrderItem::where('license_key', $key)->first();

        if ($model === null) return ['valid' => false, 'license_key' => $key, 'model' => null];

        $expected = hash_hmac('sha256', $this->canonicalize($request), $model->shared_secret);
        $given    = $request->getHeaderLine('X-License-Signature');
        if (! hash_equals($expected, $given)) {
            return ['valid' => false, 'license_key' => $key, 'model' => null];
        }

        return ['valid' => true, 'license_key' => $key, 'model' => $model];
    }
}

class CheckLicenseController
{
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $result = $this->signature->verify($request);
        if (! $result['valid']) return new JsonResponse(['error' => 'invalid_signature'], 401);

        $model = $result['model'];
        // Eager-load só o que falta — não re-query.
        $model->loadMissing($model instanceof Subscription ? ['user', 'product'] : ['order', 'product']);

        return new JsonResponse($this->present($model));
    }
}
```

Queries vão de **4 para 2** (ou 1, se você unificar `Subscription` e
`OrderItem` por um trait + polymorphic relation).

### Alternativa: merge da verificação no controller

Se o `InboundSignature` é só usado por um controlador, mover a
verificação inteira para dentro dele simplifica:

```php
public function handle(...): ResponseInterface
{
    $key = $request->getHeaderLine('X-License-Key');
    $model = Subscription::with(['user', 'product'])->where('license_key', $key)->first()
          ?? OrderItem::with(['order', 'product'])->where('license_key', $key)->first();

    if ($model === null || ! $this->verifyHmac($request, $model->shared_secret)) {
        return new JsonResponse(['error' => 'invalid_signature'], 401);
    }
    return new JsonResponse($this->present($model));
}
```

Mas, em geral, mantenha a verificação isolada na service class — o
controller fica testável e o HMAC fica reusável. Apenas garanta que o
modelo viaja junto com o resultado.

### Audit

```bash
# Para cada classe de signature, conferir se ela retorna o modelo:
rg -nE 'class\s+\w+Signature' src/Service/ | while read f; do
  rg -n 'function verify' "$f" -A 30 | grep -E 'return.*model|return.*subscription|return.*item'
done
```

Se a função `verify` só retorna um bool ou um array sem o modelo, o
chamador vai re-consultar — é finding.

### Checklist

- [ ] Toda função `verify*` que consulta um modelo no banco devolve esse
      modelo no array de retorno.
- [ ] Controladores que chamam `verify*` não fazem `Model::where(mesma_chave)`
      depois — em vez disso, `$result['model']->loadMissing(...)`.
- [ ] Endpoints públicos chamados em hot path (license check, heartbeat,
      ping) têm um teste de contagem de queries (`DB::getQueryLog()`)
      que falha se ultrapassar o budget.

---

## §60. End-to-end testing harness — auditar uma extensão Flarum contra staging

Toda extensão de produção precisa de uma camada de teste **fora do PHPUnit**
que exerce a stack inteira contra um forum real: autenticação Flarum, API
de domínio, integrações (Stripe / SES / Twilio), navegador headless com
SPA renderizada. Sem isso, o PHPUnit prova só que os pedaços compõem; não
prova que o deploy não quebra ao primeiro request real.

Esta seção descreve o harness reusável que vive em `tests/E2E/`, gente
agnóstica à extensão. Os componentes podem ser copiados para qualquer
extensão Flarum; só o conteúdo dos arrays muda.

### 60.1 Estrutura do diretório

```
tests/E2E/
├── .gitignore            # screenshots/, fixtures/, logs/, results.jsonl
├── run_e2e.py            # orquestrador — chama PHPUnit + Python suites
├── api_tests.py          # exercita cada rota HTTP com happy + failure path
├── browser_tests.py      # captura screenshots via Edge headless
├── fixtures/             # users.json, products.json criados pelo harness
├── screenshots/<area>/   # PNGs (1440×2400 desktop, 390×844 mobile)
├── api/results.jsonl     # uma linha por endpoint testado, com latency_ms
└── logs/                 # forum.json, browser.log.json
```

`.gitignore` impede que screenshots, fixtures e tokens vazem para o repo.
A pasta `fixtures/` jamais é commitada — toda credencial fica em variável
de ambiente lida pelo runner.

### 60.2 Token Flarum no harness

Flarum 2.x espera `Authorization: Token <chave>` (não `Bearer`). O token
admin é lido de `MP_API_TOKEN` — nunca é hardcoded em arquivo versionado.
O `run_e2e.py` exporta a env var antes de despachar os scripts; setá-la
no shell antes funciona igualmente.

```python
def authed(extra=None):
    headers = {"Authorization": f"Token {os.environ['MP_API_TOKEN']}",
               "Accept": "application/json"}
    if extra: headers.update(extra)
    return headers
```

Validação inicial sem custo: bater em `GET /api/users?page[limit]=1` e
afirmar que o corpo é JSON com `data`. Se voltar HTML, o header está
errado (alguém testou `Bearer`); se voltar 401, o token caducou.

### 60.3 Matriz de endpoints — happy + failure

Cada rota do `extend.php` vira UMA tupla `(area, name, method, path,
expected_http_set)`. Iteração é rasa: roda cada uma, registra latency,
salva o JSONL.

```python
pairs = [
    ("public", "products list",      "GET", "/api/myext/products",   (200,)),
    ("public", "products show 404",  "GET", "/api/myext/products/0", (404,)),
    ("admin",  "stats happy",        "GET", "/api/myext/admin/stats",(200,)),
    ("admin",  "stats as guest",     "GET", "/api/myext/admin/stats",(401,403,404)),
]
for name, method, path, exp in pairs:
    run_with_latency(suite, area, name, method, path, exp,
                     headers=authed() if area != "guest" else None)
```

A função `run_with_latency` mede `time.perf_counter()`, captura código
HTTP e excerto do corpo, e empurra um `Result` para a suite. **Cada
endpoint é exercitado com pelo menos um happy-path e uma failure-path**:
falta de auth, payload inválido, ID inexistente.

### 60.4 Stripe test-mode (quando aplicável)

Stripe expõe `pm_card_visa` (PaymentMethod sintético de teste) e a chave
secreta vem do `settings` do Flarum via admin API:

```python
secret = call_admin("/api/settings", token).get("data", {}) \
            .get("attributes", {}).get("ext.stripe_secret_key", "")
if not secret.startswith("sk_test_"):
    print("[skip] sem chave Stripe acessível, pulando real-payment flow")
    return
```

Quando há chave: criar PaymentIntent via REST, confirmar com
`payment_method=pm_card_visa`, esperar 3–10 s pelo webhook entregar o
evento, e afirmar via API que `order.payment_status == 'paid'`. Quando
não há: fabricar um evento webhook assinado com o `webhook_secret` e
POSTá-lo direto em `/api/myext/stripe/webhook`. Os efeitos colaterais
(asset claim, e-mail) devem aparecer no banco.

Documente explicitamente no relatório quando o Stripe real foi pulado —
não finja sucesso.

### 60.5 Screenshots reproduzíveis via Edge headless

Edge headless é menos pesado que Selenium para captura simples:

```python
EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

cmd = [EDGE, "--headless=new", "--disable-gpu", "--no-sandbox",
       "--enable-javascript", "--hide-scrollbars",
       f"--user-data-dir={tmp}",          # isolado por screenshot
       f"--window-size={vp}",              # 1440x2400 desktop, 390x844 mobile
       "--virtual-time-budget=5000",       # espera 5 s a SPA renderizar
       f"--screenshot={out}", url]
subprocess.run(cmd, timeout=45)
```

Pontos críticos:

1. **`--user-data-dir` único** por chamada — sem isso, Edge serializa
   tudo em uma instância e perde cookies entre páginas.
2. **`--virtual-time-budget=5000`** dá à SPA tempo para hidratar antes
   da captura — sem isso, o PNG sai com o skeleton vazio.
3. **`--enable-javascript` é redundante** (default), mas vale a sinalização
   explícita para quem ler o script depois.
4. **Não use `--headless` (legacy)** — `--headless=new` é o engine atual
   e renderiza CSS modernas (`color-mix`, `:has`).
5. **Verifique tamanho do PNG** — se < 1 KB, falhou. PNGs reais ficam
   entre 40 KB e 600 KB.

Pages típicas: home, listagem, detalhe de cada tipo de produto, carrinho
(vazio + populado), checkout, recibos, error states (404 produto, 403
admin-as-guest), e o painel admin de cada aba.

### 60.6 Webhook async — afirmar resposta < 1s

A regressão de §56 (webhook handler despachar o job em vez de processar
inline) só é provada por benchmark de latência:

```python
started = time.perf_counter()
status = call_webhook(unsigned=True)
elapsed_ms = int((time.perf_counter() - started) * 1000)
assert elapsed_ms < 1000, f"webhook respondeu em {elapsed_ms} ms — processing inline"
```

400 (invalid_signature) é a resposta esperada quando se POSTa sem
assinatura — o teste mede o caminho do controller, não o do job. Se o
controller estava processando inline antes do fix, a latência cresceria
junto com o tamanho do payload de evento.

### 60.7 Testes de regressão para findings de review

Cada finding fechado em um review merece um teste de regressão **no
nível certo de abstração** — não tente reproduzir o bug no banco quando
um assert estrutural já evita a reintrodução.

Padrões observados (que funcionam sem boot do Flarum):

| Tipo de fix | Asserção |
|---|---|
| Comportamento de método isolado | `ReflectionMethod` + `invoke` em request fake |
| Constante alterada | `assertNotContains('', Class::CONST)` |
| Controller despacha job | `assertStringContainsString('Job::dispatch', file_get_contents(...))` |
| Schema do payload | parse PHP e conferir chaves do array literal |
| Timestamps de migração únicos | `glob()` + `array_unique()` em prefixos |
| Sem `ConnectionInterface` em construtor | `assertStringNotContainsString('ConnectionInterface', source)` |

Arquivo único `Review<YYYY_MM_DD>_RegressionTest.php` por review session.
Inclua um docblock no topo enumerando os finds; o test name segue
`test_f<N>_<short_name>` para grep direto. Esse padrão sobrevive ao
refactor que viria depois — os testes falham só se o fix for revertido.

### 60.8 PHPUnit sem boot do Flarum

A maioria dos asserts de regressão NÃO precisa de boot do Flarum (sem
DB, sem container, sem migrations). O `phpunit.xml` mínimo:

```xml
<testsuites>
    <testsuite name="Unit"><directory>tests/Unit</directory></testsuite>
    <testsuite name="Integration"><directory>tests/integration</directory></testsuite>
</testsuites>
```

`bootstrap="vendor/autoload.php"` é suficiente — só PSR-4 autoload do
extension, sem inicializar a aplicação. Mockery substitui dependências
que precisariam de container.

**Cuidado**: classes que `use` traits do Laravel (`Dispatchable`,
`SerializesModels`) explodem ao serem `new`adas fora do boot Flarum. Para
elas, use `file_get_contents` + `assertStringContainsString` em vez de
`new ProcessXJob()`. Não tente bootar Flarum só para testar uma string.

### 60.9 Orquestração

`run_e2e.py` exporta envs, chama PHPUnit, depois os scripts Python em
sequência (api → browser → webhook probe). Cada etapa retorna seu
exit code; o orquestrador retorna 0 só se todos forem 0. Exemplo de uso:

```powershell
$env:MP_API_TOKEN = "..."
$env:MP_BASE_URL  = "https://staging.example.com"
python tests/E2E/run_e2e.py
```

A saída final do orquestrador é a fonte de verdade para o relatório:

```
========== Summary ==========
PASS: phpunit + api + browser + webhook latency
```

### 60.10 Quando o harness vale a pena

Critério prático: se a extensão tem ≥ 5 endpoints HTTP **OU** integra com
um provedor externo (Stripe, PayPal, GitHub, mail SaaS) **OU** o time
faz > 1 release por mês, o harness paga aluguel. Para extensões de 1–2
rotas estáticas, PHPUnit + grep manual já bastam.

### 60.11 Checklist E2E

- [ ] `tests/E2E/.gitignore` exclui screenshots, fixtures, logs, tokens.
- [ ] `MP_API_TOKEN` lido de env var, jamais hardcoded em arquivo versionado.
- [ ] Cada rota do `extend.php` aparece pelo menos uma vez em `api_tests.py`.
- [ ] Cada rota mutante tem uma assertion `as_guest -> 401/403`.
- [ ] Browser tests cobrem cada page route + os error states (404, 403).
- [ ] Webhook latency probe afirma resposta < 1 s (regressão de §56).
- [ ] Stripe real-mode ou explicitamente documentado como pulado.
- [ ] `Review<DATE>_RegressionTest.php` para cada review session, com um
      teste por finding.
- [ ] `run_e2e.py` retorna 0 só quando todas as etapas passam.

---

## §61. Traceable-conventions audit contract (alternative to §48)

**Alternative output contract to §48.** Use this contract when the user
explicitly asks for an audit against the traceable-conventions checklist defined
here — typical triggers: "use the 18-convention audit", "run the
traceable-conventions review", "use the alternative review contract",
"/audit-conventions", or any custom slug the user adopts for this style. When
the trigger is ambiguous (e.g., plain `/review`), default to §48. Only switch to
this contract when the user explicitly opts in or has saved the preference as
feedback memory.

The persona for this contract is: **senior auditor of Flarum 2.x extensions**,
deeply familiar with the official codebase (`flarum/framework` branch `2.x`),
the Friends of Flarum (FoF) conventions, and the Laravel 11/13 patterns that
Flarum 2 inherits.

### 61.0 Output language — English by default, PT-BR on request

**Default: English.** Emit the report in English unless the user explicitly
requests Brazilian Portuguese. Triggers for the PT-BR variant:

- "in PT-BR" / "em português" / "português brasileiro" / "make it Portuguese"
- "/audit-conventions pt-br" / "translate the report to PT-BR"
- A saved feedback memory recording the user's PT-BR preference for this contract.

When PT-BR is requested, swap every fixed surface string (section headings,
severity / dimension labels, verdict phrases, template scaffolding) to the
PT-BR variant. Both languages are provided in §61.6 (verdict phrases) and §61.7
/ §61.8 (full report templates). The rubric, the 18 conventions, the scoring
math, and the report structure are language-independent — only the surface
strings change.

Save the language choice as a feedback memory if the user repeats the request
across sessions.

### 61.1 Operating principles

1. **Invent nothing.** Every `file:line` citation must exist in the audited
   repository. Every class, method, namespace, or package mentioned must be
   present in the audited code or be a verifiable reference to Flarum 2 /
   Laravel.
2. **Quote short verbatim snippets** when useful for locating the problem. Use
   Grep / Glob / Read to map the codebase before writing any finding.
3. **Be technical and specific in "Fix".** No "refactor for clarity". Always
   name the concrete Flarum 2 class, method, or extender that replaces the
   anti-pattern.
4. **Do not cite Flarum 1.x.** Flarum 2 introduced massive changes:
   `ApiResource` replaces `ApiController` + `ApiSerializer`,
   `AbstractDatabaseResource` replaces `AbstractSerializer`, Laravel 13
   replaces Laravel 8, PHP 8.3 replaces PHP 7.3+. Do not recommend retired APIs.
5. **When in doubt, mark "low" and describe why.** Preferable to false positives.

### 61.2 Audit flow (execute in this order)

#### Step A — Structural mapping

Run (and cite snippets in the report when relevant):
- Read `composer.json` — extract `name`, `version`, `require.php`,
  `require.flarum/core`, `extra.flarum-extension.title`.
- Read `extend.php` — list every Extender used.
- Glob `**/*.{php,ts,tsx,js,less,json}` excluding `vendor/`, `node_modules/`,
  `dist/`, `dist-typings/`.
- Inventory `migrations/`, `src/`, `js/src/`, `resources/`.
- Read `js/tsconfig.json`, `js/package.json`.
- Read the first lines of each migration to check its format.
- Identify large PHP files (candidates for methods > 50 lines).

Use the results to fill the header (analyzed version) and have an inventory
before hunting problems.

#### Step B — Targeted scans

For each convention in §61.3, run the indicated Grep scans. For every hit, open
the file via Read, validate the context (is it a false positive?), and create a
finding with the exact `file:line`.

#### Step C — Architectural review

Evaluate:
- Is dependency injection used consistently?
- Are there DB transactions on multi-step operations?
- Is heavy aggregation cached?
- Is the API on `ApiResource` (Flarum 2) or still on the removed
  `ApiController` / `ApiSerializer` (Flarum 1)?
- Does the frontend use TypeScript with `flarum-tsconfig`?

#### Step D — Scoring and verdict

Compute Quality Score and Vibe Coded per §61.5. Decide the verdict per §61.6.

#### Step E — Report generation

Emit the report in the exact format from §61.7 (English, default) or §61.8
(PT-BR variant, on user request).

### 61.3 The 18 traceable conventions — Flarum 2.x

For each item the **anti-pattern to detect** and the **canonical Flarum 2 fix**.
These 18 items drive every scan.

#### 61.3.1 No global `resolve()` / `app()` calls
- **Detect:** `\b(resolve|app)\s*\(` in `src/` (exclude the `$app` variable; `app(` in tests can be tolerated).
- **Why:** Flarum 2 mandates constructor injection. `app()` was removed in earlier stages; `resolve()` is discouraged in production (couples, blocks testing, breaks under Octane).
- **Canonical fix:** receive `Illuminate\Contracts\Container\Container` (or the concrete dependency) in the constructor. In Service Providers, use `$this->container` in `register()` and the type-hinted argument in `boot(Container $container)`.

#### 61.3.2 Mandatory migration helpers
- **Detect:** `use Illuminate\\Database\\Schema\\Builder|'up' => function` in `migrations/`.
- **Anti-pattern:** returning `['up' => function (Builder $schema) {...}, 'down' => ...]` and calling `$schema->create(...)` or `$schema->table(...)` directly.
- **Canonical fix:** use the static helpers on `Flarum\Database\Migration`:
  - `Migration::createTable($name, fn (Blueprint $table) => …)`
  - `Migration::createTableIfNotExists($name, fn (Blueprint $table) => …)`
  - `Migration::renameTable($from, $to)`
  - `Migration::addColumns($table, [...])` / `Migration::dropColumns($table, [...])`
  - `Migration::renameColumn($table, $from, $to)` / `Migration::renameColumns($table, [...])`
  - For defaults: `Migration::addSettings([...])` and `Migration::addPermissions([...])`.
- **Flarum 2 / Laravel 11+ note:** when altering columns, you MUST repeat the full column definition (including `->nullable()`), because Laravel 11+ does not preserve modifiers implicitly.

#### 61.3.3 PHP ≥ 8.3 required
- **Detect:** `"php"\s*:` in `composer.json`.
- **Anti-pattern:** `"php": "^8.2"`, `"^8.1"`, `">=8.0"`, or no constraint at all.
- **Canonical fix:** `"php": "^8.3"`. Flarum 2.0 requires PHP 8.3+; `flarum/core` v2.0.0-rc.1 (2026-04-18) declares exactly `"php": "^8.3"`.

#### 61.3.4 Laravel / Flarum Filesystem instead of native functions
- **Detect:** `\b(file_get_contents|file_put_contents|fopen|fwrite|fclose|fread|unlink|rename|mkdir|rmdir|is_dir|is_file|file_exists|copy|move_uploaded_file|scandir|glob)\s*\(` in `src/`.
- **Anti-pattern:** using native PHP for any read/write into directories Flarum manages (assets, avatars, uploads, attachments).
- **Canonical fix:** inject `Illuminate\Contracts\Filesystem\Factory` and obtain the appropriate disk (`flarum-assets`, `flarum-avatars`, or a custom disk registered via `Extend\Filesystem`). Read with `$disk->get($path)`, write with `$disk->put($path, $contents)`, delete with `$disk->delete($path)`. See `Flarum\Api\Controller\DeleteLogoController` as reference.
- **Tolerated exception:** reading files from the extension's own package (resources/views, locale, etc.).

#### 61.3.5 Frontend must use TypeScript + `flarum-tsconfig`
- **Detect:**
  - `js/tsconfig.json` must exist.
  - `flarum-tsconfig` must be in `js/package.json` devDependencies.
  - TS files must exist in `js/src`.
- **Anti-pattern:** only `.js` / `.jsx` in `js/src`, no `tsconfig.json`, or no `flarum-tsconfig` in devDependencies.
- **Canonical fix:** `npm install --save-dev flarum-tsconfig@^2.0.0` and create `js/tsconfig.json` extending `flarum-tsconfig`. For Flarum 2: `flarum-webpack-config: ^3.0.0`, `flarum-tsconfig: ^2.0.0`.

#### 61.3.6 `$dates` on models is retired
- **Detect:** `protected \$dates` in `src/`.
- **Anti-pattern:** `protected $dates = ['some_at'];` on Eloquent models. Deprecated in Laravel 8, **removed in Laravel 10**; Flarum 2 uses Laravel 13.
- **Canonical fix:** `protected $casts = ['some_at' => 'datetime'];`. To extend other models, use `(new Extend\Model(User::class))->cast('some_at', 'datetime')`. `Extend\Model::dateAttribute()` is deprecated.

#### 61.3.7 Mass assignment — `$guarded = []`
- **Detect:** `protected \$guarded\s*=\s*\[\s*\]` in `src/`.
- **Anti-pattern:** `$guarded = []` disables all mass-assignment protection.
- **Canonical fix:** define `$fillable` explicitly, or list sensitive fields in `$guarded` (e.g. `['id', 'is_admin']`).

#### 61.3.8 Long functions and deep nesting (technical debt)
- **Detect:** for each `.php` in `src/`, count method line counts. Methods with **> 50 lines** or nesting > 3 levels → "medium" technical-debt finding.
- **Canonical fix:** decompose into private methods named after the domain (`assertNotFlooding()`, `extractMetadata()`, `persistRevision()`). See also §53.

#### 61.3.9 N+1 queries
- **Detect:** `foreach` loops that invoke an Eloquent relation method without prior `with()` / `load()`.
- **Anti-pattern:** `foreach ($discussions as $d) { $d->user->name; }` without `Discussion::with('user')->...`.
- **Canonical fix:** eager loading via `->with([...])`, `->withCount([...])`, `->load([...])` or, in Flarum 2, via `Endpoint\Index::make()->eagerLoad(['user'])` on the `ApiResource`. See §38.1.

#### 61.3.10 Caching of heavy aggregations
- **Detect:** controllers / listeners / serializers running `count()`, `sum()`, `groupBy()` over growing tables (`posts`, `users`, `orders`, `discussions`) without caching.
- **Canonical fix:** inject `Illuminate\Contracts\Cache\Repository`, wrap with `$cache->remember($key, $ttl, fn() => $query)` (TTL 60s–1h depending on volatility). Invalidate via listeners on the modifying events. Heed §24 (per-actor cache keys).

#### 61.3.11 Correct extenders in `extend.php`
- **Detect:** `extend.php` returning closures (`function (Dispatcher $events) { … }`) instead of `Extend\*` objects. In Flarum 2, a strong smell of badly-ported code.
- **Valid Flarum 2 extenders:** `Extend\Frontend`, `Extend\Routes`, `Extend\Model`, `Extend\ModelVisibility`, `Extend\ModelPrivate`, `Extend\ModelUrl`, `Extend\ApiResource` (replaces `ApiController` and `ApiSerializer`), `Extend\Event`, `Extend\Console`, `Extend\Settings`, `Extend\ServiceProvider`, `Extend\Policy`, `Extend\Notification`, `Extend\Filesystem`, `Extend\Filter`, `Extend\Formatter`, `Extend\Middleware`, `Extend\Post`, `Extend\Theme`, `Extend\View`, `Extend\Validator`, `Extend\LanguagePack`, `Extend\Locales`, `Extend\Mail`, `Extend\Session`, `Extend\ThrottleApi`, `Extend\SearchDriver`, `Extend\User`, `Extend\Link`, `Extend\Preload`, `Extend\Conditional`.
- **Anti-pattern in Flarum 2:** `Extend\ApiController` or `Extend\ApiSerializer` — **removed**. Migration is to `Extend\ApiResource(...)` pointing at a class extending `Flarum\Api\Resource\AbstractDatabaseResource` (or `AbstractResource`) and defining `fields()`, `endpoints()`, `sorts()` via `Flarum\Api\Schema\*` and `Flarum\Api\Endpoint\*`.
- **Also removed:** `AbstractSerializeController`, `AbstractShowController`, `AbstractCreateController`, `AbstractUpdateController`, `AbstractDeleteController`, `AbstractSerializer`, `DiscussionValidator`, `PostValidator`, `UserValidator`, `TagValidator`, `GroupValidator`, `SuspendValidator`, and the `flarum.forum.discussions.sortmap` singleton.

#### 61.3.12 Security
- **Input validation:** endpoint inputs must pass through `Flarum\Foundation\AbstractValidator` (or through validations declared on `Schema\Str::make(...)->rule(...)->maxLength(...)->regex(...)` fields of an `ApiResource`). Detect any `$request->getParsedBody()` or `Arr::get($input, ...)` without validation.
- **Secret comparison:** grep `===|!=` on lines mentioning `token|secret|signature|hmac` — sensitive compares must use `hash_equals($expected, $provided)`.
- **Path traversal in ZIPs / uploads:** require a resolved `realpath()` + `str_starts_with($real, $baseDir . DIRECTORY_SEPARATOR)`. See §13.
- **Exception messages:** `throw new \Exception($e->getMessage())` or returning `$e->getMessage()` to the user can leak paths / secrets. Map to types known to `Flarum\Foundation\ErrorHandling\Registry` or use white-listed messages.
- **Client MIME:** never trust `$file->getClientMediaType()`. Detect server-side with `finfo_file(finfo_open(FILEINFO_MIME_TYPE), $tmpPath)` or `getimagesize()` for images. See §11.
- **Unsanitized SVG:** detect `accept image/svg+xml` or `mimes:svg` without `enshrined/svg-sanitize` or equivalent. See §9.5.
- **`libxml_use_internal_errors`:** missing restore via `libxml_use_internal_errors($previous)` is a high-severity finding — leaks global state to other extensions and to the next request in long-running environments.
- **Path traversal in LESS:** values interpolated into LESS (via `Extend\Settings::registerLessConfigVar()`) must be validated — Flarum has suffered CVE-2023-27577 and GHSA-xjvc-pw2r-6878 from injectable `@import (inline)` in theme settings.

#### 61.3.13 Race conditions in sequential numbering
- **Detect:** assigning sequential numbers (`post_number`, `order_number`, `sequence`) computed via `max() + 1` or `count() + 1` without an isolated transaction.
- **Canonical fix:** wrap in `DB::transaction(function () { ... })` with `lockForUpdate()` on the aggregating query, use a separate `auto_increment` column, or use an `INSERT IGNORE`-style "claim" pattern.

#### 61.3.14 Transactions on multi-step operations
- **Detect:** sequences of `->save()`, `->update()`, `->insert()` over related tables, followed by event dispatch, without `DB::transaction(...)`.
- **Canonical fix:** `DB::transaction(function () use (...) { $post->save(); $discussion->update(...); event(new Posted($post)); });`.

#### 61.3.15 Sensitive data leakage via API
- **Detect:** in `ApiResource::fields()`, fields like `Schema\Str::make('client_secret')`, `'webhook_secret'`, `'internal_domain'`, `'api_token'` etc. exposed without `->hidden()` or without `->visible(fn($m, $ctx) => $ctx->getActor()->isAdmin())`.
- **Canonical fix:** mark as `->hidden()` or gate visibility on the actor. For inheritance via `mutate()`, always filter before returning. See §6.

#### 61.3.16 In-memory pagination
- **Detect:** materializing entire collections (`->get()->filter(...)->slice($offset, $limit)`) instead of paginating in SQL.
- **Canonical fix:** apply `where()`, `orderBy()`, `limit()`, `offset()` on the query builder. In the Flarum 2 API, configure `Endpoint\Index::make()->paginate($default, $max)`. See §38.5.

#### 61.3.17 Dead code
- **Detect:**
  - `@deprecated` in `src/`.
  - `TODO|FIXME|XXX` in `src/` and `js/src/`.
  - Unused imports (`use Foo;` with no reference to `Foo` in the file).
  - Private methods with no internal caller.
- **Canonical fix:** delete. If kept for compatibility, document the reason and the planned removal date. See §31.

#### 61.3.18 Static state in utility classes
- **Detect:** classes with `protected static $cache = []` or similar that accumulate state across the process. In queue workers and Laravel Octane, this leaks across requests.
- **Canonical fix:** convert into a container-registered singleton (`$container->singleton(Foo::class)`), with state in instance properties. See §44.2.

### 61.4 Flarum 2 features the auditor must know

To write "Fix" correctly, know the confirmed stack:

- **Stack (Flarum core v2.0.0-rc.1, 2026-04-18):** PHP `^8.3`, `illuminate/*` at `^13.0` (Laravel 13), Carbon `^3.8.4`, Symfony 7.2 (transitive via Laravel 13), Mithril 2.2, `doctrine/dbal: ^3.6`, `dflydev/fig-cookies: ^3.0`, `guzzlehttp/guzzle: ^7.7`, `flarum/json-api-server: ^0.1.0`, `fortawesome/font-awesome: ^7.0`.
- **API layer:** `Flarum\Api\Resource\AbstractDatabaseResource` (Eloquent models) or `AbstractResource` (virtual resources); fields via `Flarum\Api\Schema\Str|Number|Boolean|DateTime|Arr|Relationship\ToOne|Relationship\ToMany`; endpoints via `Flarum\Api\Endpoint\Index|Show|Create|Update|Delete`; policies via `->can('permission')` or a Policy class.
- **Search:** `AbstractSearcher` (replaces `AbstractFilterer`), filters via classes in `Flarum\Search\Filter`; gambits moved to the frontend.
- **DB drivers in 2.0:** MySQL, MariaDB, SQLite, and PostgreSQL supported; use `whenMysql`, `whenSqlite`, `whenPgsql` on the query builder for vendor-specific SQL, and declare `extra.database-support` in `composer.json` when needed.
- **Mithril 2.2:** `vnode.text` stores the text of a single child; use `extractText()` in extensions.
- **Frontend imports:** `import X from 'ext:vendor/extension/common/...'` (the `ext:` prefix is mandatory in 2.0).
- **Logout:** `POST /logout` (route `logout`) + `GET /logout` (route `logoutPage`).
- **Translator:** prefer `Flarum\Locale\TranslatorInterface` over `Symfony\Contracts\Translation\TranslatorInterface`.
- **Avatars:** static avatars are converted to WebP; animated GIFs are preserved.
- **Settings:** inject `Flarum\Settings\SettingsRepositoryInterface`. Defaults via `Migration::addSettings([...])` or `Extend\Settings::default(...)`.
- **Permissions:** inject `Flarum\User\User` and use `$actor->can('permission')`. Defaults via `Migration::addPermissions([...])` or `Extend\Policy`.
- **Events:** `(new Extend\Event)->listen(Event::class, Listener::class)`. The listener is resolved by the container and receives DI in its constructor.

### 61.5 Scoring system

#### 61.5.1 Quality Score (0–100)

Start at **100**. Subtract:

| Finding severity | Penalty |
|---|---|
| High | −15 |
| Medium | −5 |
| Low | −2 |

**Additional adjustments (applied after the raw subtraction):**

- **Structural penalties (cumulative, max −20):**
  - −10 if `extend.php` still uses `Extend\ApiController` or `Extend\ApiSerializer` (Flarum 1 → 2 migration not done).
  - −5 if there are no automated tests at all (`tests/` empty or missing).
  - −5 if there is no `tsconfig.json` / `flarum-tsconfig`.
  - −5 if there is no caching anywhere in hot paths that aggregate.
- **Bonuses (cumulative, max +10):**
  - +3 if there are integration tests using `flarum/testing`.
  - +3 if dependency injection is consistent across 100% of classes.
  - +2 if transactions and caching are used appropriately.
  - +2 if there is clear `README.md` documentation and full TypeScript typings.

**Bands:**
- 90–100: production-ready, exemplary extension.
- 75–89: ready with caveats; improvements recommended but not blocking.
- 50–74: requires substantial work before production.
- 0–49: not recommended for production use.

Round to integer. Floor: 0.

**Calibration note:** this rubric differs from §48.3 (which uses −25/−8/−3/−2
weights with per-dimension caps and a floor of 20). §61 is harsher on High
(−15 vs −8) and more lenient on Critical — appropriate to a contract that
treats "High" as the publication cut-off. Do not mix the two rubrics in the
same report.

#### 61.5.2 Vibe Coded (0–100)

**0 = clear experienced-human authorship. 100 = clear unrevised AI generation.**

Weigh the signals; add points per observed signal, plus 10 extra points if
≥ 4 signals appear together.

**AI signals (add points):**
- Redundant "explanatory" comments that restate the code (`// loop through each user` before `foreach ($users as $user)`): **+10**.
- Inconsistent naming across files (`getUser`, `fetch_user`, `retrieveUserData` for the same operation): **+10**.
- Blanket `try { ... } catch (\Exception $e) { Log::error($e); }` on every method, no type distinction: **+10**.
- Repetitive validation patterns that ignore Flarum's `AbstractValidator`: **+5**.
- Unneeded "defensive" variables (`if (!is_null($x) && $x !== '' && !empty($x))` instead of a truthy check): **+5**.
- Generic English exception messages ("Something went wrong", "An error occurred") with no context: **+5**.
- Methods with `@return mixed` or `@param mixed` docblocks: **+3**.
- Unused imports or random import ordering: **+3**.
- Reinvented utility functions instead of using Laravel / Flarum (`function slugify($s)` instead of `Str::slug`): **+5**.
- Use of non-Flarum idioms (`Auth::user()` instead of the injected actor, `DB::table('users')` instead of the `User` model): **+5**.

**Human-authorship signals (subtract):**
- Contextual comments explaining *why*, not *what* (`// We can't use Cache::tags() because the file driver doesn't support it`): **−10**.
- Specific optimizations with reference to a known issue / PR: **−5**.
- Idiomatic use of Flarum utilities (`Extend\Conditional`, `ModelVisibility` with a thoughtful closure, `Schema\Str::make()->set(fn ...)`): **−10**.
- Idiosyncratic decisions justified in a comment: **−5**.
- Edge-case handling with matching tests: **−5**.

**Bands:**
- 0–25: clearly experienced human.
- 26–50: probably human with occasional AI assistance.
- 51–75: probably AI-generated with shallow review.
- 76–100: strong "vibe coded" signal, no critical review.

Floor / cap: 0 / 100.

### 61.6 Production verdict (bilingual)

Pick **exactly one** of the two phrases below. The verdict UI does an exact
string match, so reproduce the chosen phrase verbatim in the chosen language.

| Outcome | English (default) | Brazilian Portuguese (on request) |
|---|---|---|
| Approved with caveats | `Approved with caveats; may need some adjustments to be safe for production use` | `Aprovado com ressalvas; pode necessitar de alguns ajustes para ser seguro para uso em produção` |
| Not production-ready | `This extension is not safe for production in its current state and requires specific fixes before it can be listed` | `Esta extensão não é segura para produção em seu estado atual e requer correções específicas antes de poder ser listada` |

Pick the row by the same rule in either language:

- **"Approved with caveats"** — when **no** "high"-severity finding exists in
  the `security` or `production risk` dimensions, **AND** Quality Score ≥ 70.
- **"Not production-ready"** — when there is **at least one** "high" finding in
  `security` or `production risk`, **OR** Quality Score < 70, **OR** `extend.php`
  still uses removed Flarum 1 APIs (`ApiController` / `ApiSerializer` /
  `AbstractSerializeController` / etc.).

### 61.7 English report template (default)

Emit **only** this Markdown at the end, substituting placeholders. No preamble,
no postscript beyond what is here.

````markdown
# Code review

This review was produced by Claude Code under the traceable-conventions audit
contract for Flarum v2 extensions.

**Status:** {verdict from §61.6, verbatim, English column}

- **Analyzed version:** {package name from `composer.json` @ git version/tag, or short commit}
- **Reviewed at:** {ISO 8601 local}
- **Quality Score:** {0–100}/100
- **Vibe Coded:** {0–100}/100

## Executive summary

- {Sentence 1 — publication verdict in objective language, with the score as support}
- {Sentence 2 — top scalability / performance issue with a concrete scenario. Ex.: "On a forum with 50,000 posts, `GET /api/extension/stats` runs an uncached `COUNT(*)` on every request — with 10 moderators on the admin page concurrently, that is 10 full scans/min."}
- {Sentence 3 — overall architectural assessment, positive where merited, citing security, domain knowledge, edge-case handling}
- {Sentence 4 — query efficiency and overall performance, citing presence/absence of eager loading, caching, transactions}

## Findings

### {Descriptive title of finding 1}
- **Severity:** high | medium | low
- **Dimension:** conventions | security | technical debt | production risk | robustness | dead code | performance
- **Location:** `relative/path/File.php:LINE` (or range `:START-END`)
- **Problem:** {2–5 sentences describing concretely what is wrong, citing the relevant snippet; explain the operational impact}
- **Fix:** {Specific technical instruction naming the concrete Flarum 2 class / method / extender that should replace the anti-pattern. No generic prose.}

### {Descriptive title of finding 2}
- **Severity:** ...
- **Dimension:** ...
- **Location:** ...
- **Problem:** ...
- **Fix:** ...

{... repeat for every finding, ordered by Severity (high → low) and within a severity by Dimension (security → production risk → robustness → performance → conventions → technical debt → dead code). If the extension is clean, still emit at least 2–3 honest "low" findings to demonstrate that the scan happened.}
````

### 61.8 PT-BR report template (on user request)

When the user explicitly requested Brazilian Portuguese, emit this template
instead. The structure is identical to §61.7; only the surface strings change.

````markdown
# Revisão de código

Esta revisão foi produzida com Claude Code sob o contrato de auditoria por
convenções rastreáveis para extensões Flarum v2.

**Status:** {veredito da §61.6, verbatim, coluna português}

- **Versão analisada:** {nome do pacote do `composer.json` @ versão git/tag, ou commit curto}
- **Data/hora da revisão:** {ISO 8601 local}
- **Pontuação de Qualidade:** {0–100}/100
- **Codificado pela vibração:** {0–100}/100

## Sumário executivo

- {Frase 1 — veredito de publicação em linguagem objetiva, com a Pontuação como suporte}
- {Frase 2 — principal problema de escalabilidade/performance com cenário concreto. Ex.: "Em um fórum com 50 000 posts, o endpoint `GET /api/extension/stats` executa um `COUNT(*)` não cacheado a cada request — em uma página de admin aberta por 10 moderadores simultâneos, isso é 10 full scans/min."}
- {Frase 3 — avaliação arquitetural geral, positiva quando merecido, citando segurança, conhecimento de domínio, casos extremos tratados}
- {Frase 4 — avaliação de eficiência de consultas e performance geral, citando presença/ausência de eager loading, cache e transações}

## Resultados

### {Título descritivo do finding 1}
- **Gravidade:** alto | médio | baixo
- **Dimensão:** convenções | segurança | dívida técnica | risco de produção | robustez | código morto | performance
- **Localização:** `caminho/relativo/Arquivo.php:LINHA` (ou intervalo `:LINHA_INICIAL-LINHA_FINAL`)
- **Problema:** {2–5 frases descrevendo concretamente o que está errado, citando o trecho relevante; explique o impacto operacional}
- **Consertar:** {Instrução técnica específica nomeando as classes/métodos/extenders concretos do Flarum 2 que devem substituir o padrão errado. Sem genéricos.}

### {Título descritivo do finding 2}
- **Gravidade:** ...
- **Dimensão:** ...
- **Localização:** ...
- **Problema:** ...
- **Consertar:** ...

{... repetir para todos os findings, ordenados por Gravidade (alto → baixo) e dentro de cada gravidade por Dimensão (segurança → risco de produção → robustez → performance → convenções → dívida técnica → código morto). Se a extensão for limpa, ainda gere ao menos 2–3 findings "baixo" para demonstrar que a varredura foi feita.}
````

**PT-BR label mapping** (use these exact strings when generating the PT-BR
report so it remains grep-stable):

| English label | Portuguese label |
|---|---|
| Code review | Revisão de código |
| Status | Status |
| Analyzed version | Versão analisada |
| Reviewed at | Data/hora da revisão |
| Quality Score | Pontuação de Qualidade |
| Vibe Coded | Codificado pela vibração |
| Executive summary | Sumário executivo |
| Findings | Resultados |
| Severity | Gravidade |
| Dimension | Dimensão |
| Location | Localização |
| Problem | Problema |
| Fix | Consertar |
| high / medium / low | alto / médio / baixo |
| conventions | convenções |
| security | segurança |
| technical debt | dívida técnica |
| production risk | risco de produção |
| robustness | robustez |
| dead code | código morto |
| performance | performance |

### 61.9 Example findings (tone calibration)

**Use these examples as style references only.** Do not copy verbatim or invent
analogous situations; generate findings **only about what exists in the audited
repository**. Examples below are in English; when the user requested PT-BR,
translate the register naturally and use the label mapping in §61.8.

#### Example A — high / security

```
### Non-constant-time comparison of webhook token enables timing oracle
- **Severity:** high
- **Dimension:** security
- **Location:** `src/Webhook/IncomingController.php:42`
- **Problem:** the controller compares the received signature with `$expected === $request->getHeader('X-Signature')[0]`. PHP's `===` short-circuits on the first divergent byte, creating a remote timing oracle. An attacker can infer secret bytes in ~256 requests per byte with stable network latency.
- **Fix:** switch to `hash_equals($expected, (string) ($request->getHeader('X-Signature')[0] ?? ''))`. `hash_equals()` is the constant-time comparison primitive recommended by OWASP and used by Flarum itself in `Flarum\Http\AccessToken`.
```

#### Example B — high / production risk

```
### Migration uses raw Schema instead of Flarum helpers
- **Severity:** high
- **Dimension:** production risk
- **Location:** `migrations/2024_03_10_000000_create_widgets_table.php:8-25`
- **Problem:** the migration returns `['up' => function (Builder $schema) {...}, 'down' => ...]` and calls `$schema->create('widgets', ...)` directly. On installs where the extension has been enabled and partially purged, the table may already exist and the migration crashes with `Base table or view already exists`. The down is not idempotent either.
- **Fix:** replace with `return Flarum\Database\Migration::createTableIfNotExists('widgets', function (Illuminate\Database\Schema\Blueprint $table) { $table->increments('id'); $table->string('name', 191); $table->timestamps(); });`. For later-added columns, use `Migration::addColumns($table, [...])` which generates the `down` automatically.
```

#### Example C — medium / performance

```
### Widget listing N+1 on `user` relation
- **Severity:** medium
- **Dimension:** performance
- **Location:** `src/Api/Resource/WidgetResource.php:38`
- **Problem:** `Schema\Relationship\ToOne::make('user')->includable()` is available as include, but the `Endpoint\Index` does not declare `eagerLoad(['user'])`. When the frontend requests `?include=user` for 50 widgets, 51 queries fire (1 + 50). With 200 active widgets and cache off, the admin page is ~1.2 s just on DB.
- **Fix:** in `endpoints()`, change the Index entry to `Endpoint\Index::make()->eagerLoad(['user'])->paginate(20, 50)`. Confirm with a query log that a JOIN or subselect occurs.
```

#### Example D — medium / conventions

```
### Global `resolve()` used instead of DI
- **Severity:** medium
- **Dimension:** conventions
- **Location:** `src/Listener/NotifyOnPosted.php:19`
- **Problem:** the listener obtains `SettingsRepositoryInterface` via `resolve(SettingsRepositoryInterface::class)` inside `handle()`. This breaks the Flarum 2 DI rule, makes the class untestable without a full framework boot, and is problematic in long-running environments (Octane, persistent queue workers) where the container state may have been recycled.
- **Fix:** move the dependency to the constructor: `public function __construct(private SettingsRepositoryInterface $settings) {}`. The container resolves the listener automatically via `Extend\Event::listen(Posted::class, NotifyOnPosted::class)`.
```

#### Example E — low / dead code

```
### Unused import of `Illuminate\Support\Arr`
- **Severity:** low
- **Dimension:** dead code
- **Location:** `src/Api/Resource/WidgetResource.php:7`
- **Problem:** `use Illuminate\Support\Arr;` is declared but `Arr::` is not referenced anywhere in the file. Small noise, but a signal that automated review (PHPStan / Larastan) is missing.
- **Fix:** delete the line. Consider wiring `flarum/phpstan` in `composer.json` and running `vendor/bin/phpstan analyse` in CI to block regressions.
```

### 61.10 Final constraints

- **Do not execute the extension's code** — analysis is static.
- **Do not download real dependencies** — if `vendor/` or `node_modules/` exist, ignore them for scope.
- **Do not fabricate findings** if the extension is genuinely good. In that case, emit only 2–3 honest "low" findings and keep the score high.
- **If the extension is Flarum 1.x** (detected by `"flarum/core": "^1.0"` or `"^0.1"` in `composer.json`), emit a single "high" finding under `conventions` titled *"Extension is not compatible with Flarum 2.x"* and stop. Do not audit against 2.x rules.
- **Report language:** English by default; Brazilian Portuguese when the user explicitly requested it (see §61.0). Code identifiers (classes, methods, namespaces) keep their original form in either language.
- **Expected report length:** 800–2,500 words depending on codebase size.

### 61.11 How this contract relates to §48

| Aspect | §48 (default contract) | §61 (this contract) |
|---|---|---|
| Trigger | `/review`, `/security-review`, `/ultrareview`, "review this" | "use the 18-convention audit", "/audit-conventions", or any custom slug the user adopts |
| Output language | English | English (default), PT-BR on explicit user request |
| Quality rubric | −25/−8/−3/−2 with per-dimension caps, floor 20 | −15/−5/−2 with cumulative structural penalties + bonuses, floor 0 |
| Vibe score | 0–100 (positive / negative signals with weights) | 0–100 (AI tells with +N; human-authorship tells with −N) |
| Verdict phrases | Three bands: ≥80, 75–79, < 75 | Two canonical phrases (binary gated by severity + score) |
| Findings shape | 5-column table (severity, dimension, title, impact) | Findings as expanded list (severity, dimension, location, problem, fix) |
| Pre-emit prompt | Asks "full report or punch list?" | Emits directly, no pre-prompt |

**Disambiguation rule:** when the trigger is unclear, default to §48 in English.
To opt into this §61 contract, the user must explicitly name it (e.g.
"traceable-conventions audit", "18-convention review", or a custom slug they
adopt). Save the preference as a feedback memory if the user repeats the choice
across sessions. The same rule applies to the language: default English, PT-BR
only when explicitly asked.

---

## §62. Multi-write atomicity & DB transactions

A request handler, observer, or job that writes to **two or more rows/tables** and
fails mid-way leaves the database in a state no one can reconcile: an `Order` with
`payment_status=pending` and only half its `OrderItem`s persisted, a stock counter
decremented without the row that consumed it, a `Subscription` created by an Observer
that fired off a parent `Order` event the controller never knew about. The
ERROR_HANDLING audit of a real marketplace extension found **only two `transaction()`
calls in the entire backend** while a dozen multi-write financial flows ran unprotected.

### Locate

```bash
rg -n "->save\(\)|::create\(|->update\(|->insert\(|->delete\(\)|->decrement\(" src/
rg -n "transaction\(|DB::transaction|getConnection\(\)->transaction" src/
```

For every controller/job/observer with **2+ writes** in `src/`, confirm a transaction
wraps them. Checkout, webhook fulfillment, order-activation save, any "create parent +
N children + bump a counter" shape — all need one.

### Red flags

- `Order::create(...)` followed by a `foreach` of `OrderItem::create(...)` with no transaction — failure on item N persists N−1 orphans.
- An `Observer::saved()` that calls `Subscription::create(...)` — it runs *inside* the parent model's save, but the surrounding controller's writes are not in the same transaction unless the controller opened one.
- Sequential numbering (`post_number`, `order_number`) computed via `max()+1` / `count()+1` with no `lockForUpdate()` — two concurrent requests collide on the same number.
- `Illuminate\Support\Facades\DB::transaction(...)` — the `DB` facade root may be unset in some request/queue contexts (§10).
- A webhook handler that re-runs fulfillment on Stripe's re-delivery because the work isn't idempotent.

### Correct shape

```php
// Open the transaction off the model's own connection — never the DB facade,
// never a constructor-injected ConnectionInterface (§10).
Order::query()->getConnection()->transaction(function () use ($cart, $billing) {
    $order = new Order();
    $order->user_id = (int) $actor->id;
    $order->save();

    foreach ($cart->items() as $item) {
        $line = new OrderItem();
        $line->order_id = $order->id;
        $line->save();
        Product::query()->whereKey($item->productId)->lockForUpdate()->decrement('stock');
    }

    $order->payment_status = 'paid';
    $order->save();
});
```

### Webhook idempotency

A webhook can be delivered more than once. Before the transaction, guard on a unique
event id; inside, use `firstOrCreate` for any row the re-delivery would duplicate:

```php
if (WebhookEvent::query()->where('event_id', $event->id)->exists()) {
    return new JsonResponse(['received' => true, 'deduped' => true]);
}
// ... inside the transaction:
OrderActivation::firstOrCreate(
    ['order_id' => $order->id, 'product_id' => $product->id],
    ['status' => 'pending']
);
```

A `UNIQUE` index on `event_id` is the authoritative guard — the application-level
`exists()` check is racy under concurrency; pair it with `try/catch (QueryException)`
on the insert.

### Reference

ERROR_HANDLING_AUDIT flagged `CreateCheckoutController` (`Order` + N×`OrderItem` +
stock decrement + `OrderActivation` + N×`ActivationValue` + `$order->save()`) and
`StripeWebhookController::handleSessionCompleted` (`$order->save` + `upsertSubscription`
+ `recordCoupon` + `claimAssets` + `provisionUser` + `sendWelcome`) as unprotected
multi-write flows. Both must be one transaction each, with the webhook idempotency
guard *before* the transaction opens.

---

## §63. Request-derived state must be memoized

A value derived inside a request — a session key, a scope identifier, a context hash —
that is **recomputed on every call** from a non-deterministic source (`random_bytes`,
`uniqid`, `microtime`) produces a different value each time. If three layers of the
same request (controller → service → totals) each call `derive()`, each sees a
distinct value, and one layer's work is invisible to the next.

### The phantom-cart bug (real incident)

`CartManager::scope()` minted a guest's session key via `bin2hex(random_bytes(16))`
when no `marketplace_cart` cookie was present. The handler called `scope()` **three
times per request** (controller → `add()` → `totals()`), each producing a different
random key:

- The item persisted under key A.
- The cookie was returned with key B.
- `totals()` queried under key C → returned `count: 0`.

`POST /cart/items` returned HTTP 201 with `{id: 140}` — a phantom row no client could
ever reach (`PATCH`/`DELETE` on that id returned 422 "not found"). The response
contradicted itself: `id: 140` alongside `totals.count: 0`.

### Locate

```bash
rg -n "random_bytes|uniqid|bin2hex|microtime|Str::random" src/Service/ src/Api/
```

For each hit, ask: is this value consumed more than once in the same request? If so,
it must be memoized.

### Correct shape

Memoize per `ServerRequestInterface` instance, keyed by `spl_object_id`:

```php
class CartManager
{
    /** @var array<int, string> */
    private array $scopeCache = [];

    public function scope(ServerRequestInterface $request): string
    {
        $oid = spl_object_id($request);
        if (isset($this->scopeCache[$oid])) {
            return $this->scopeCache[$oid];
        }

        $cookie = FigRequestCookies::get($request, 'marketplace_cart')->getValue();
        $key = $cookie ?: bin2hex(random_bytes(16));

        return $this->scopeCache[$oid] = $key;
    }
}
```

All three calls within one request now return the same key. For a guest's first write,
force-`save()` the parent entity (Cart) **before** creating the child (CartItem) so the
FK exists at insert time.

### Never return an unconfirmed `id`

The `POST` response returned `id: 140` before persistence was confirmed. **Returning a
fake id is worse than returning nothing** — the client composes
`PATCH /cart/items/140` and gets a 422. Only include the `id` after re-reading the row
(or confirming the `count` from the joined totals, not from a fresh re-query).

### Cross-reference

§44.2 covers *static* state leaking across requests in workers; this section is the
inverse — derived state that should persist **within** a request and doesn't. Both are
fixed by tying the state's lifetime to the correct lifecycle (the request), never to a
`static` and never to a recompute.

---

## §64. Validate input SHAPE before semantic rules

Business-rule validators (`min_two_products`, `amount > 0`, `status in [...]`) assume
the input already has the expected **format**. When the client sends a different shape,
PHP extraction functions **fail silently** — they return `[]` or `null` instead of
throwing — and every downstream semantic validator runs over empty data and passes.

### The `array_column` footgun (real incident)

`CreateBundleController` expected `items` in the object shape
(`[{product_id, quantity}]`) and ran `array_column($items, 'product_id')`. When the
client sent the legacy flat int-array shape (`[25, 26]`), `array_column` returned `[]`.
`$productIds = []` skipped every subsequent validation. The bundle was created with a
name + price and **zero products**. The `min_two_products` validator ran *after* the
silent drop, so it never fired.

### Locate

```bash
rg -n "array_column|array_map|array_filter|Arr::pluck" src/Api/ src/Service/
rg -n "getParsedBody\(\)|\[.data.\]\[.attributes.\]" src/
```

### Red flags

- `array_column($x, 'k')` / `Arr::pluck` over a body without first asserting each entry has the expected shape.
- A business-rule validator that runs **after** an extraction that could have returned `[]`.
- Duplicate keys in an array literal — `['type' => 'a', /* ... */ 'type' => 'b']` — PHP silently keeps the last one. `ListProductsController` had two `'type'` keys in the `->map()`-serialized item; the second silently overwrote the first.

### Correct shape

Validate the shape **before** any semantic rule, with an explicit failure:

```php
private function normalizeProductsInput(mixed $items): array
{
    if (! is_array($items)) {
        throw new ValidationException(['items' => 'invalid_products_shape']);
    }
    $out = [];
    foreach ($items as $entry) {
        if (! is_array($entry) || ! isset($entry['product_id'])) {
            throw new ValidationException(['items' => 'invalid_products_shape']);  // rejects the legacy array
        }
        $out[] = [
            'product_id' => (int) $entry['product_id'],
            'quantity'   => (int) ($entry['quantity'] ?? 1),
        ];
    }
    return $out;
}
```

Shape validation runs before `min_two_products` and every other rule. Apply the same
guard in `UpdateBundleController` — otherwise a `PATCH` with the legacy shape silently
wipes an existing bundle's products.

For array-literal keys: visually review every large `->map()` / `return [` block — two
keys of the same name at the same level is always a bug.

---

## §65. HTTP status & API surface symmetry

The status code and the route shape are a contract. When the status lies about the
real effect, or when one endpoint's response doesn't compose into a route that exists,
the client makes wrong decisions — and the bug is invisible in code review because each
piece, in isolation, "works".

### Red flags (API surface audit)

```bash
rg -n "EmptyResponse\(204\)|JsonResponse\([^,]+, 20" src/Api/
rg -n "->get\(|->post\(|->patch\(|->delete\(" extend.php
```

- **204 masquerading as soft-delete.** `DELETE /products/{id}` that flips `active=false`
  and returns `204 No Content`. The client reads 204 as "row gone"; the row stays in the
  DB. An idempotent re-`DELETE` returns 204 again, so the client can't distinguish
  "never existed" from "I deleted it" from "already inactive". Return
  `200 {data: {id, archived: true, hard_deleted: false}}` with a class docblock
  explaining the archive semantics — or rename it to `POST /{id}/archive`.

- **A `create` response that doesn't compose into a read route.** `POST /licenses`
  returns `{id: N}`, inviting the client to build `GET /licenses/{id}` — which 404s
  because only `by-key/{key}` and `{scope}/{id}` exist. If `create` returns an `id`,
  a `GET /{id}` that resolves it must exist.

- **405 vs 404 — asymmetric CRUD verbs.** Registering only `PATCH` and `DELETE` on
  `/bundles/{id}` leaves `GET` falling into the "method not allowed" branch. A **405**
  means "the route exists for other verbs but not this one"; a **404** means "the route
  doesn't exist". Admin SPAs often refetch via the index + client-side filter, which
  masks a missing `GET /{id}` — that's why it's a recurring blind spot.

### Audit discipline

When auditing an API, **probe every CRUD verb against every resource path**. Index /
create / patch / delete passing while `GET /{id}` 405s is the exact shape of marketplace
findings F3/F4/F6. For every `create` that returns an `id`, register the matching
`Show` (`ShowBundleAdminController`, `ShowLicenseByScopeController`,
`ShowProductAdminController` were all created to close this gap).

---

## §66. One trigger per state-change effect

When an effect (claim an asset, provision a user, send a welcome email, create a
pending activation) can be triggered by **more than one path** — an Eloquent Observer
and an explicit service, say — and both run on the same transition, the effect executes
**twice**.

### The double-fulfillment bug (real incident)

A marketplace order's post-payment effects ran twice for Stripe orders:

- `OrderObserver::saved()` fired **synchronously, inside** the `EventProcessor`'s
  transaction (under a row lock).
- The `EventProcessor` then **repeated** claim/provision/welcome after commit.

### Correct shape — split responsibility by origin

Use a **discriminating column** to make the two paths mutually exclusive:

```php
class OrderObserver
{
    public function saved(Order $order): void
    {
        if ($order->payment_status !== 'paid') {
            return;
        }
        // Stripe orders are finalized by the EventProcessor (from the webhook).
        // The observer stays the canonical trigger only for non-Stripe orders.
        if (! empty($order->stripe_session_id)) {
            return;
        }
        $this->claimForOrder($order);
        $this->provisionUser($order);
        $this->sendWelcome($order);
    }
}
```

With the observer out of the Stripe path, the `EventProcessor` takes over **and** also
creates the pending-activation records the observer used to create — idempotently,
*post-commit*:

```php
private function createPendingActivations(Order $order): void
{
    foreach ($order->items as $item) {
        if ($item->product?->activation_mode !== 'manual') {
            continue;
        }
        OrderActivation::firstOrCreate(                       // idempotent — survives re-delivery
            ['order_id' => $order->id, 'product_id' => $item->product_id],
            ['status' => 'pending']
        );
    }
}
```

### General rule

- A state-change effect has **exactly one trigger per origin**.
- When an Observer and a service can both fire on the same transition, split them by a
  discriminating column; the guard comes **after** the status early-return and
  **before** the first effect.
- Webhook re-entrant work is always idempotent (`firstOrCreate`, never `create`).
- Test the behavior by booting Eloquent over SQLite `:memory:`, degrading to
  `markTestSkipped` when `pdo_sqlite` is absent; assert each collaborator is called
  **exactly once** per origin.

### Cross-reference

§20 (listeners/observers and actor identity), §62 (webhook idempotency). This section
is about the *count* of triggers; §20 is about *who* triggers.

---

## §67. Error-handling completeness

A swallowed error is worse than a thrown one: the user clicks "Save", nothing happens,
they click again, and the form ends up in a state no one can reconstruct. The
ERROR_HANDLING audit of a real extension found error handling systematically absent —
an API wrapper with no instrumentation, ~15 of 25 loading components with no error
state, seven-plus empty `catch` blocks, and **zero** `console.*` calls in the entire
frontend (when something fails, the error doesn't even reach DevTools).

§40 covers frontend robustness point-by-point; this section is the **structure** that
ensures no failure path is left orphaned.

### 67.1 — Instrumented central API wrapper

A 14-line `api.ts` that just forwards `app.request()` returning `Promise<any>` delegates
100% of error handling to callers — who routinely forget. Attach a central `.catch()`
that fires a generic alert on 5xx/network errors and **re-throws** so the caller can
still handle the specific case:

```ts
export function api<T = unknown>(opts: FlarumRequestOptions): Promise<T> {
  return app.request<T>(opts).catch((e) => {
    const status = e?.status ?? 0;
    if (status === 0 || status >= 500) {
      app.alerts.show({ type: 'error' }, app.translator.trans('myext.network_error'));
    }
    throw e;                                                  // re-throw — the caller handles 4xx
  });
}
```

### 67.2 — Every loading component has three explicit states

A component with `loading` but no `error` renders a network failure **identically** to
"empty list" / "not found". The standard state is `{ loading, error, data }` and the
`view` renders all three distinctly:

```ts
view() {
  if (this.loading) return <LoadingIndicator />;
  if (this.error)   return <div className="myext-error">{this.error}
                              <Button onclick={() => this.load()}>{app.translator.trans('core.lib.retry')}</Button></div>;
  if (!this.data?.length) return <p className="muted">{app.translator.trans('myext.empty')}</p>;
  return /* success */;
}
```

"Empty" and "network failure" must never look the same.

### 67.3 — Mithril has no `componentDidCatch`

Mithril (Flarum's framework) has no React-style error boundary; a render exception in
any component crashes the whole page tree. Two defenses:

1. An `ErrorBoundary extends Component` component that `try`s `vnode.children` and
   stores `caughtError`, used around each route/page and around each third-party
   widget/embed (never one per component — boundary-inside-boundary is a smell).
2. A global listener registered in `forum/index.tsx` **and** `admin/index.tsx`:

```ts
window.addEventListener('unhandledrejection', (e) => {
  app.alerts.show({ type: 'error' }, app.translator.trans('myext.unexpected_error'));
  // structured log — see §67.5
});
```

Boundaries do **not** catch event-handler errors, async errors, or SSR errors.

### 67.4 — `fetch()` does not reject on HTTP error status

`fetch()` resolves normally on a 4xx/5xx — it only rejects on a network failure. An
upload via `fetch()` that doesn't check `res.ok` shows "saved" even when the backend
rejected, leaving a product with no file:

```ts
const res = await fetch(url, { method: 'POST', body: form });
if (!res.ok) {
  throw new Error(`upload failed: ${res.status}`);
}
```

### 67.5 — Backend: no empty `catch`, no over-narrow type

```bash
rg -n "catch\s*\([^)]*\)\s*\{\s*\}" src/                    # fully empty catch
rg -n "catch\s*\(\\\\DomainException" src/                   # possibly over-narrow type
rg -n "@file_get_contents|@file_put_contents|@fopen" src/    # error-suppressed I/O
```

- An empty **`catch (\Throwable) {}`** in a financial operation (the refund fallback
  that lost the second error in an empty `catch`) is total error loss — always log +
  re-throw.
- **`catch (\DomainException)`** in a controller lets any other exception (DB, Stripe
  connection) become a generic HTTP 500. Catch `\Throwable` with explicit mapping:
  `DomainException` → 422, the rest → log + 500.
- **`@fopen`/`@file_get_contents`** suppresses the error; check the return value
  (`=== false`) and log structured. Inject `LoggerInterface` (§41) — never recover from
  an error without leaving a trace.

### 67.6 — UX failure-strategy matrix

| Failure | Strategy |
|---|---|
| GET fails | inline error + reload button |
| Write fails | toast + keep the form filled |
| Optimistic action fails | revert local state + toast |
| Timeout | specific message + retry with backoff (max 2×) |
| 4xx | server message inline at the field |
| 5xx | generic message + correlation id |
| 401 | redirect to login preserving the route |
| 403 | dedicated page (not 404) |
| 404 | differentiate from "empty list" |

---

## §68. Debug/maintenance scripts never ship in the package

A loose PHP file in the extension root — `fix_db.php`, `view_logs.php`, `test_boot.php`,
`enable_ext.php`, `read_sys_logs.php`, `catch_migration.php` — is not just poor hygiene.
If the extension is installed under a webroot, **each one becomes an unauthenticated
HTTP endpoint** anyone on the internet can trigger.

### The incident (real extension)

The `extend-ads` extension shipped **eight** debug scripts in its root:

- `fix_db.php` — opens a raw PDO connection from `config.php` and **`DELETE`s rows from
  the `migrations` table** with no authentication. Anyone reaching
  `https://forum/.../extend-ads/fix_db.php` destroys the forum's migration state.
- `view_logs.php` / `read_sys_logs.php` / `latest_error.php` — dump Apache/nginx/PHP/
  Flarum logs (hardcoded paths) to any request — direct information disclosure.
- `enable_ext.php` / `test_boot.php` — boot the application and enable an extension with
  no auth.

Severity: 🔴 high when the extension root is servable, 🟠 medium otherwise — but always
a release-blocker finding.

### Locate

```bash
# Any .php in the extension root other than extend.php
find . -maxdepth 1 -name '*.php' ! -name 'extend.php' 2>/dev/null
# Debug-named scripts anywhere
rg -l "new PDO\(|->boot\(\)|ExtensionManager.*enable|file_get_contents\(.*\.log" --glob '!vendor' --glob '!src' .
```

Any `.php` in the root other than `extend.php` is suspect. `src/` holds only
PSR-4-autoloaded classes; executable scripts belong nowhere in the package.

### Rule

- **Delete them all.** Diagnostics live on a dev branch, in a gist, or in `tests/` —
  never in a package that goes to Packagist. If you need a maintenance command, write an
  `Extend\Console` command (runs via `php flarum`, requires shell access, is not an HTTP
  endpoint).
- **Hardcoded paths from another machine** (`e:/laragon/...` in a repo that lives on
  `d:/laragon/...`) confirm the script is debug junk — it wouldn't even find the files
  on the current machine.
- **`.agent.md` / scaffolding metadata** with stale paths: clean or delete.

### Vendoring a third-party dependency

Related: the `websocket` extension autoloaded
`"BeyondCode\\LaravelWebSockets\\": "BeyondCode/src/"` — a **copy of the source code** of
`beyondcode/laravel-websockets` embedded in the repo instead of declared as a
dependency. Vendored copies miss security patches and bloat the package. Always
`composer require` the package; remove the copied `src/`. (Cross-ref §43 — dependency
contracts.)

### Phantom controllers with Laravel-Framework idioms

Still in the "code that should never have shipped" family: `extend-ads` had two upload
controllers, and the unwired one (`UploadImageController`) used `response()->json(...)`
and `public_path(...)` — Laravel Framework helpers that **do not exist in Flarum** (same
family as the `Illuminate\Foundation\Bus\Dispatchable` trap in §56). It would fatal if
invoked. Delete it: it's dead code that is also a latent fatal.

```bash
rg -n "response\(\)->|public_path\(|base_path\(|storage_path\(|view\(|redirect\(\)" src/
```

Any hit in a Flarum extension's `src/` is a Laravel-Framework helper that doesn't exist
— either the file is dead, or it will fatal in production.

---

## When in doubt

1. **Read the relevant section above end-to-end** before writing code. This file is the single source of truth.
2. If a pattern isn't covered, grep the reference extensions for the closest analogue.
3. If still uncertain, **ask the user**. A confirming question costs nothing; a shipped vulnerability costs everything.
4. **Never disable security primitives "temporarily"** — `bypassCsrfToken`, `forceAllow`, `$guarded = []`, raw `m.trust` of unsanitized input, `ApiKey` with `user_id = NULL`, returning `false` from a throttler "to exempt admins". Temporary becomes permanent.
5. After committing, run `php -l`, `npm run build`, and at minimum a manual smoke test of the affected screens.