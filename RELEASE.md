# Rilascio su GitHub Releases

Il progetto compila un **fat jar eseguibile** (shaded, autosufficiente) con librerie esterne
integrate (`bcprov`, `bcpg`, `xz`). Il canale di distribuzione è **GitHub Releases**: il push di
un tag `vX.Y.Z` attiva il workflow `.github/workflows/release.yml`, che costruisce il fat jar,
calcola lo SHA-256 e crea la Release con i file allegati.

## Prerequisiti

- Working tree **pulito** (nessuna modifica non committata).
- `mvn` disponibile in locale (la release usa `mvn release:prepare`).
- Branch attivo: `master`.

## Passo 1 — Rilasciare con `mvn release:prepare`

```bash
mvn release:prepare
```

Con la configurazione in `pom.xml`, questo fa tutto da solo:
- porta la versione da `X.Y.Z-SNAPSHOT` a `X.Y.Z` e committa `release vX.Y.Z`;
- crea il tag **annotato** `vX.Y.Z`;
- committa il "next baseline" (`X.Y.(Z+1)-SNAPSHOT`).

(`pushChanges=false`: committ e tag restano in locale, il push è manuale — passo successivo.)

## Passo 2 — Push (avvia il workflow)

```bash
git push origin master
git push origin vX.Y.Z
```

Il push del tag `vX.Y.Z` attiva il workflow che, automaticamente:
1. legge `project.version` dal pom (il commit del tag ha la versione di rilascio);
2. esegue `mvn package` → `target/pgp-tool-X.Y.Z.jar` (fat jar);
3. genera `target/pgp-tool-X.Y.Z.jar.sha256`;
4. crea la GitHub Release `vX.Y.Z` con i due file e note generate dai commit.

## Note

- **Nessuna firma GPG né pubblicazione su Maven Central**: `maven-gpg-plugin` e
  `central-publishing-maven-plugin` sono stati rimossi dal pom (canale di distribuzione = GitHub).
- **Tag `v`-prefissato**: `tagNameFormat` è `v@{version}` e il workflow ascolta `tags: ['v*']`.
- **Versione a 3 componenti**: mantenere `X.Y.Z-SNAPSHOT` nel pom (es. `1.0.0-SNAPSHOT`), così
  `release:prepare` genera `X.Y.Z` → tag `vX.Y.Z` (con `1.0-SNAPSHOT` uscirebbe `v1.0`).
- **Retry del workflow su un tag esistente**: la Release per quel tag esiste già; per aggiornarla
  usare `update_release_assets: true` / `update_release_body: true` nell'action, oppure eliminarla
  prima del retry.
- `dependency-reduced-pom.xml` (byproduct dello shade) è in `.gitignore`.
