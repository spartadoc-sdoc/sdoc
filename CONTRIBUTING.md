# Contribuer à sdoc

Merci de votre intérêt pour le format ouvert `.sdoc`.

## Développement local

```bash
git clone https://github.com/spartadoc-sdoc/sdoc.git
cd sdoc
npm install
npm run build      # compile src/ → dist/
npm test           # tests codec + CLI (round-trip)
npm run typecheck  # vérification de types sans émettre
```

## Périmètre

Ce dépôt est l'**implémentation de référence d'un standard**. Priorités :

1. **Interopérabilité** : tout changement du format binaire doit être reflété
   dans `spec/sdoc-format.md` et rester rétro-compatible en lecture.
2. **Zéro couplage produit** : le codec et le CLI ne dépendent d'aucun service.
   Pas d'authentification, pas d'appel réseau.
3. **Dépendances minimales** : le codec ne dépend que de `@noble/post-quantum`.

## Compatibilité de format

Le format v1.x est **figé** (dérivation de clé incluse, cf. spec §4). Les
évolutions cryptographiques (ex. HKDF RFC 5869 strict) passeront par une **v2.0**
avec un nouvel octet `version`, en conservant la lecture des versions antérieures.

## Sécurité

Merci de **ne pas** ouvrir d'issue publique pour une vulnérabilité. Contactez
l'équipe en privé (voir https://sdoc.ca).

## Licence des contributions

En contribuant, vous acceptez que votre contribution soit distribuée sous
Apache-2.0 (cf. LICENSE §5).
