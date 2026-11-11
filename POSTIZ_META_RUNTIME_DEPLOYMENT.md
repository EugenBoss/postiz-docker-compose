# Postiz Meta OAuth — preflight de deployment și rollback

Acest document activează doar un **preflight**. Nu pornește Postiz, nu
autorizează Meta și nu publică nimic. El este poarta dintre overlay-ul local și
un runtime HTTPS demonstrabil, înainte de canarul Facebook + Instagram.

## Criteriul de trecere

Operatorul produce un JSON strict sanitizat cu imaginea care rulează, numai
variabilele non-secrete de mai jos, numele secretelor Docker și o observație
proaspătă că nu există callback OAuth în curs. Nu include `DATABASE_URL`,
cookie-uri, tokenuri, chei, dump-uri de mediu sau valori de secret.

```json
{
  "image": "registry.example/postiz@sha256:<64-hex>",
  "environment": {
    "POSTIZ_INTEGRATION_TOKEN_ACTIVE_KEY": "k2026_11",
    "POSTIZ_INTEGRATION_TOKEN_KEYS_FILE": "/run/secrets/postiz_integration_token_keys",
    "POSTIZ_INTEGRATION_TOKEN_LEGACY_MODE": "reject",
    "POSTIZ_META_REVOCATION_SIGNING_KEY_FILE": "/run/secrets/postiz_meta_revocation_signing_key",
    "POSTIZ_META_REVOKE_APPLY": "NO"
  },
  "secrets": ["postiz_integration_token_keys", "postiz_meta_revocation_signing_key"],
  "oauth_callbacks": {
    "in_flight": 0,
    "quiesced": true,
    "observed_at": "<UTC ISO-8601, maximum 5 minutes old>"
  }
}
```

Se rulează imediat după citirea independentă a runtime-ului:

```sh
node postiz-token-envelope/runtime-preflight.mjs \
  --origin https://postiz.example.com \
  --expected-image registry.example/postiz@sha256:<64-hex> \
  --runtime-file /safe/path/runtime-preflight.json
```

Rezultatul acceptat este unicul JSON cu `status:"pass"`. Scriptul refuză
origini fără HTTPS, tag-uri mutabile, orice câmp de mediu neașteptat, secrete
inline, keyring absent, revocare armată și observații OAuth vechi sau active.
`postiz-token-envelope/fixtures/runtime-preflight-sample.json` este numai un
exemplu de formă fără secrete; timestamp-ul lui este intenționat vechi și nu
poate constitui un preflight. Inputul real trebuie recoltat din runtime chiar
înaintea comenzii.

## Ordinea de deployment

1. Construiește și publică overlay-ul revizuit cu un digest imutabil; nu folosi
   `latest`. Păstrează digestul anterior ca rollback.
2. Montează cele două secrete exclusiv file-only și lasă
   `POSTIZ_META_REVOKE_APPLY=NO`. Rulează dry-run-ul de migrare și păstrează
   backup-ul PostgreSQL înainte de orice migrare aplicată, conform
   `POSTIZ_META_TOKEN_ENCRYPTION.md`.
3. Servește o origine HTTPS publică stabilă și înregistrează exact callback-urile
   raportate de preflight. Nu începe OAuth până nu există un rezultat `pass`
   citit din runtime-ul nou.
4. După `pass`, control-plane-ul Admin rămâne cu publicarea automată oprită și
   kill switch-ul armat. Abia atunci se poate cere un singur login/OTP Meta în
   Postiz pentru alegerea identităților brandului; urmează read-back 2/2, fără
   creare de postări, drafturi sau programări.

## Rollback verificabil

Dacă orice criteriu de preflight, OAuth sau read-back eșuează:

1. păstrează kill switch-ul activ și oprește noi callback-uri OAuth;
2. revino la digestul imutabil anterior și configurația precedentă, fără a
   șterge cheia veche sau baza;
3. citește înapoi imaginea efectivă, sănătatea HTTPS și faptul că nu există
   apeluri `POST /public/v1/posts`, drafturi ori programări;
4. marchează orice integrare Meta nouă ca neactivă/eroare până la reconcilierea
   controlată. Nu revoca providerul ca parte din rollback-ul de deployment.

Runtime-ul Orion nu este presupus a fi ținta: deploymentul poate continua numai
pe un host care poate demonstra imaginea, secretele file-only, Postgres/Redis/
Temporal și originea HTTPS. Absența unui fișier cunoscut de Compose nu este
dovadă că un alt host îndeplinește contractul.
