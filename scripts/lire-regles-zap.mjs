#!/usr/bin/env node
// lire-regles-zap — lit les règles de balayage de l'image ZAP épinglée par oracle-dast et les écrit dans
// referentiels/zap-regles.json (TF-2476, TF-2477). Rien n'est téléchargé et rien n'est émis : l'image doit
// déjà être sur le poste (`docker image inspect`), et les deux conteneurs lancés tournent avec
// `--network none`. Le premier lit les add-ons de `/zap/plugin` (zip) et en tire les noms de règles ; le
// second demande à ZAP lui-même, par `-cmd -silent -addonlist`, quelles versions d'add-ons il charge, et le
// script refuse d'écrire si ces versions ne sont pas celles qu'il a lues (l'image porte deux versions de
// chaque add-on : ZAP charge la plus haute, et c'est elle dont les noms comptent).
//
// Ce qui est lu : pour chaque add-on de règles, les valeurs des clés `*.name` et `*.alert.name` de ses
// fichiers de messages. C'est un SURENSEMBLE des noms d'alerte (il contient aussi des libellés d'interface) :
// un nom absent de la liste n'est jamais une règle de l'image, un nom présent n'en est pas la preuve.
// Partition posée ici : actives = ascanrules, domxss ; passives = pscanrules, authhelper, retire ;
// autres = les autres add-ons dont le manifeste déclare une règle (soap, scripts), non classés.
//
// Usage : node scripts/lire-regles-zap.mjs --image <référence avec empreinte> [--ecrire | --verifier]
//   (sans option : affiche le JSON) · --verifier rend 1 si referentiels/zap-regles.json diffère de la lecture
//   (hors `lu_le`) · une image absente du poste rend 2, sans rien tirer.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ICI = path.dirname(fileURLToPath(import.meta.url));
const SORTIE = path.join(ICI, "..", "referentiels", "zap-regles.json");
const args = process.argv.slice(2);
const opt = (nom) => { const i = args.indexOf(nom); return i >= 0 ? args[i + 1] : null; };
const image = opt("--image");
if (!image || !/@sha256:[0-9a-f]{64}$/.test(image)) {
  console.error("--image <dépôt@sha256:empreinte> est obligatoire : la lecture est celle d'une image épinglée par empreinte");
  process.exit(2);
}
const docker = (a, delai = 120000) => spawnSync("docker", a, { encoding: "utf8", timeout: delai, maxBuffer: 64 * 1024 * 1024 });
const absente = docker(["image", "inspect", image, "--format", "{{.Id}}|{{.Created}}"], 30000);
if (absente.error || absente.status !== 0) {
  console.error(`image ${image} absente du poste (ou Docker injouable) : rien n'est tiré, la lecture s'arrête`);
  process.exit(2);
}
const [idImage, creee] = absente.stdout.trim().split("|");

const PYTHON = String.raw`
import glob, json, os, re, zipfile
def cle(v):
    return tuple(int(x) if x.isdigit() else 0 for x in v.split("."))
retenus = {}
presentes = {}
for f in glob.glob("/zap/plugin/*.zap"):
    m = re.match(r"^(.+?)-(release|beta|alpha)-(.+)\.zap$", os.path.basename(f))
    ident, statut, version = m.groups()
    presentes.setdefault(ident, []).append(version)
    if ident not in retenus or cle(version) > cle(retenus[ident][1]):
        retenus[ident] = (f, version, statut)
ACTIVES = ["ascanrules", "domxss"]
PASSIVES = ["pscanrules", "authhelper", "retire"]
sortie = {"modules": [], "actives": {}, "passives": {}, "autres": {}}
jar = sorted(glob.glob("/zap/zap-*.jar"))
sortie["zap"] = re.sub(r"^zap-|\.jar$", "", os.path.basename(jar[0])) if jar else None
for ident in sorted(retenus):
    f, version, statut = retenus[ident]
    z = zipfile.ZipFile(f)
    xml = z.read("ZapAddOn.xml").decode("utf8", "replace")
    declare = len(re.findall(r"<(?:pscanrule|ascanrule)>", xml))
    if ident not in ACTIVES + PASSIVES and not declare:
        continue
    noms = set()
    for n in z.namelist():
        if n.endswith("/Messages.properties") and not n.startswith("org/mozilla"):
            for l in z.read(n).decode("utf8", "replace").splitlines():
                m = re.match(r"^([A-Za-z0-9_.-]+?)\.(?:alert\.)?name\s*=\s*(.+?)\s*$", l)
                # la clé « <id>.name » est le libellé de l'add-on quand il porte des règles (pscanrules, ascanrules) ;
                # pour un add-on d'une seule règle sans manifeste de règles (domxss, retire) c'est le nom de l'alerte.
                if m and not (declare and m.group(1) == ident) and not m.group(1).endswith(".payloader"):
                    noms.add(m.group(2))
    rang = "actives" if ident in ACTIVES else ("passives" if ident in PASSIVES else "autres")
    sortie[rang][ident] = sorted(noms)
    sortie["modules"].append({"id": ident, "version": version, "statut": statut, "versions_presentes": sorted(presentes[ident], key=cle), "classe": rang, "noms": len(noms)})
sortie["charges"] = {i: r[1] for i, r in retenus.items()}
print(json.dumps(sortie, ensure_ascii=False))
`;
const lu = docker(["run", "--rm", "--network", "none", "--entrypoint", "python3", image, "-c", PYTHON]);
if (lu.status !== 0) { console.error(`lecture des add-ons en échec : ${lu.stderr || lu.error}`); process.exit(1); }
const brut = JSON.parse(lu.stdout);

// Contre-lecture : ce que ZAP charge, dit par ZAP. Ligne : « nom<TAB>id<TAB>vN.N.N<TAB>statut<TAB>description ».
const chaine = docker(["run", "--rm", "--network", "none", "--entrypoint", "/zap/zap.sh", image, "-cmd", "-silent", "-addonlist"], 170000);
const normaliser = (v) => v.replace(/^v/, "").split(".").map(Number).reduceRight((a, n) => (a.length === 0 && n === 0 ? a : [n, ...a]), []).join(".");
const chargeesParZap = {};
for (const l of String(chaine.stdout).split(/\r?\n/)) {
  const c = l.split("\t");
  if (c.length >= 4 && /^v\d/.test(c[2])) chargeesParZap[c[1]] = normaliser(c[2]);
}
const desaccords = [];
for (const m of brut.modules) {
  const vu = chargeesParZap[m.id];
  if (vu === undefined) desaccords.push(`${m.id} : absent de la liste de ZAP`);
  else if (vu !== normaliser(m.version)) desaccords.push(`${m.id} : lu ${m.version}, chargé par ZAP ${vu}`);
}
if (!Object.keys(chargeesParZap).length || desaccords.length) {
  console.error(`contre-lecture refusée (${Object.keys(chargeesParZap).length} add-ons listés par ZAP) : ${desaccords.join(" ; ") || "liste vide"}`);
  process.exit(1);
}

const empreinte = image.slice(image.indexOf("@") + 1);
const resultat = {
  schema: 1,
  _usage: "Données lues dans l'image ZAP épinglée par oracle-dast, jamais saisies à la main : les produit `node scripts/lire-regles-zap.mjs --image <référence> --ecrire` et les contrôle le self-test. Les listes sont un SURENSEMBLE des noms d'alerte (libellés d'interface compris) : un nom absent n'est pas une règle de l'image, un nom présent n'en prouve pas l'alerte.",
  image: { reference: image, empreinte, id_local: idImage, creee: creee.slice(0, 19) + "Z", zap: brut.zap },
  lu_le: new Date().toISOString().slice(0, 10),
  lecture: "docker run --rm --network none --entrypoint python3 <image> -c <lecture des zip de /zap/plugin> ; contre-lecture par docker run --rm --network none --entrypoint /zap/zap.sh <image> -cmd -silent -addonlist (versions chargées identiques, add-on par add-on)",
  modules: brut.modules,
  actives: brut.actives,
  passives: brut.passives,
  autres: brut.autres,
  absents_de_l_image: {
    modules: ["ascanrulesBeta", "pscanrulesBeta"],
    note: "zap-baseline.py et zap-full-scan.py lancent `-addonupdate` puis `-addoninstall pscanrulesBeta` (et `ascanrulesBeta` pour le balayage complet) sauf si les options ZAP portent `-silent` : ces deux add-ons ne sont pas dans l'image, ils viennent du réseau au lancement, et leurs règles sont donc hors de ces listes. oracle-dast passe `-silent` à l'image (TF-2477).",
  },
};
const texte = JSON.stringify(resultat, null, 2) + "\n";
if (args.includes("--ecrire")) {
  fs.writeFileSync(SORTIE, texte);
  console.error(`écrit : ${SORTIE} (${brut.modules.length} modules, ${Object.values(brut.actives).flat().length} noms actifs, ${Object.values(brut.passives).flat().length} noms passifs)`);
} else if (args.includes("--verifier")) {
  const sansDate = (t) => JSON.stringify({ ...JSON.parse(t), lu_le: null });
  const actuel = fs.existsSync(SORTIE) ? fs.readFileSync(SORTIE, "utf8") : "{}";
  if (sansDate(actuel) !== sansDate(texte)) { console.error("referentiels/zap-regles.json diffère de la lecture de l'image"); process.exit(1); }
  console.error("referentiels/zap-regles.json identique à la lecture de l'image");
} else process.stdout.write(texte);
